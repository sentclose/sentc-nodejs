import {AbstractAsymCrypto} from "./crypto/AbstractAsymCrypto";
import {
	FileCreateOutput,
	FileMetaInformation,
	FilePrepareCreateOutput,
	GroupKeyRotationOut,
	GroupOutDataHmacKeys,
	USER_KEY_STORAGE_NAMES,
	UserData,
	UserKeyData,
	UserPublicKeyData
} from "./Enities";
import {
	changePassword,
	decodeJwt,
	deleteDevice,
	deleteUser,
	getFreshJwt,
	groupCreateGroup,
	groupDecryptHmacKey,
	groupPrepareCreateGroup,
	prepareRegisterDevice,
	registerDevice,
	resetPassword,
	userCreateSafetyNumber,
	userDeviceKeySessionUpload,
	userFinishKeyRotation,
	userKeyRotation,
	userPreDoneKeyRotation,
	UserData as NativeUserData,
	updateUser,
	registerRawOtp,
	registerOtp,
	getOtpRecoverKeys,
	resetRawOtp,
	resetOtp,
	disableOtp,
	getUserDevices,
	groupGetGroupsForUser,
	groupGetInvitesForUser,
	groupAcceptInvite,
	groupRejectInvite,
	groupJoinReq,
	groupGetSentJoinReqUser,
	groupDeleteSentJoinReqUser,
	fileDeleteFile,
	fileFileNameUpdate,
	fetchUserKey
} from "@sentclose/sentc_node_js";
import {REFRESH_ENDPOINT, Sentc} from "./Sentc";
import {getGroup, prepareKeys} from "./Group";
import {Downloader, findAvailableFileName, Uploader} from "./file";
import {SymKey} from ".";
import {
	create_error,
	GroupInviteListItem,
	GroupList,
	OtpRegister,
	UserDeviceList
} from "@sentclose/sentc-common";
import {FileHandle} from "node:fs/promises";
import * as path from "path";

async function setUserStorageData(user_data: UserData, deviceIdentifier: string) {
	const storage = await Sentc.getStore();

	const store_user_data = user_data;

	if (Sentc.options.refresh.endpoint !== REFRESH_ENDPOINT.api) {
		//if the refresh token should not be stored on the client -> invalidates the stored refresh token
		//but return the refresh token with the rest of the user data
		store_user_data.refresh_token = "";
	}

	return storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + deviceIdentifier, store_user_data);
}

export async function getUser(deviceIdentifier: string, data: NativeUserData, mfa: boolean)
{
	//Only fetch the older keys when needed; this is not like a group where all keys must be available

	//user key map
	const key_map = new Map<string, number>();
	const user_keys: UserKeyData[] = [];

	for (let i = 0; i < data.userKeys.length; i++) {
		const key = data.userKeys[i];

		key_map.set(key.groupKeyId, i);

		user_keys.push({
			group_key_id: key.groupKeyId,
			verify_key: key.verifyKey,
			exported_verify_key: key.exportedVerifyKey,
			time: +key.time,
			sign_key: key.signKey,
			public_key: key.publicKey,
			exported_public_key_sig_key_id: key.exportedPublicKeySigKeyId,
			exported_public_key: key.exportedPublicKey,
			group_key: key.groupKey,
			private_key: key.privateKey
		});
	}

	const newest_key_id = data.userKeys[0].groupKeyId;

	const user_data: UserData = {
		newest_key_id,
		key_map,
		user_keys,
		hmac_keys: [],
		mfa,
		jwt: data.jwt,
		user_id: data.userId,
		device_id: data.deviceId,
		refresh_token: data.refreshToken,
		device: {
			exported_verify_key: data.keys.exportedVerifyKey,
			verify_key: data.keys.verifyKey,
			exported_public_key: data.keys.exportedPublicKey,
			public_key: data.keys.publicKey,
			sign_key: data.keys.signKey,
			private_key: data.keys.privateKey
		}
	};

	const store_user_data = user_data;

	if (Sentc.options.refresh.endpoint !== REFRESH_ENDPOINT.api) {
		//if the refresh token should not be stored on the client -> invalidates the stored refresh token
		//but return the refresh token with the rest of the user data
		store_user_data.refresh_token = "";
	}

	const user = new User(Sentc.options.base_url, Sentc.options.app_token, user_data, deviceIdentifier);

	//decrypt the hmac key
	const hmacKeys: GroupOutDataHmacKeys[] = [];

	for (let i = 0; i < data.hmacKeys.length; i++) {
		const k = data.hmacKeys[i];
		hmacKeys.push({key_data: k.keyData, group_key_id: k.groupKeyId});
	}

	const decrypted_hmac_keys = await user.decryptHmacKeys(hmacKeys);
	user.user_data.hmac_keys = decrypted_hmac_keys;
	store_user_data.hmac_keys = decrypted_hmac_keys;

	//save user data in indexeddb
	const storage = await Sentc.getStore();

	await Promise.all([
		storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + deviceIdentifier, store_user_data),
		storage.set(USER_KEY_STORAGE_NAMES.actualUser, deviceIdentifier),
		//save always the newest public key
		storage.set(USER_KEY_STORAGE_NAMES.userPublicKey + "_id_" + user_data.user_id, <UserPublicKeyData>{
			public_key: user_data.user_keys[0].exported_public_key,
			public_key_id: user_data.user_keys[0].group_key_id,
			public_key_sig_key_id: user_data.user_keys[0].exported_public_key_sig_key_id,
			verified: false
		}),
		storage.set(
			USER_KEY_STORAGE_NAMES.userVerifyKey + "_id_" + user_data.user_id + "_key_id_" + user_data.user_keys[0].group_key_id,
			user_data.user_keys[0].exported_verify_key
		)
	]);

	return user;
}

export class User extends AbstractAsymCrypto
{
	constructor(
		base_url: string,
		app_token: string,
		public user_data: UserData,
		private userIdentifier: string,
		public group_invites: GroupInviteListItem[] = []
	) {
		super(base_url, app_token);
	}

	private async getUserKeys(key_id: string, first = false)
	{
		let index = this.user_data.key_map.get(key_id);

		if (index === undefined) {
			//try to fetch the keys from the server
			await this.fetchUserKey(key_id, first);

			index = this.user_data.key_map.get(key_id);

			if (index === undefined) {
				//key not found
				throw new Error("Key not found");
			}
		}

		const key = this.user_data.user_keys[index];

		if (!key) {
			//key not found
			throw new Error("Key not found");
		}

		return key;
	}

	private getUserKeysSync(key_id: string)
	{
		const index = this.user_data.key_map.get(key_id);

		if (index === undefined) {
			throw new Error("Key not found");
		}

		const key = this.user_data.user_keys[index];

		if (!key) {
			//key not found
			throw new Error("Key not found");
		}

		return key;
	}

	async getUserSymKey(key_id: string): Promise<string>
	{
		const key = await this.getUserKeys(key_id);

		return key.group_key;
	}

	async getPrivateKey(key_id: string): Promise<string>
	{
		const key = await this.getUserKeys(key_id);

		return key.private_key;
	}

	getPrivateKeySync(key_id: string): string
	{
		const key = this.getUserKeysSync(key_id);

		return key.private_key;
	}

	getPublicKey(reply_id: string): Promise<UserPublicKeyData>
	{
		return Sentc.getUserPublicKeyData(this.base_url, this.app_token, reply_id);
	}

	getNewestHmacKey(): string
	{
		return this.user_data.hmac_keys[0];
	}

	private getNewestKey()
	{
		let index = this.user_data.key_map.get(this.user_data.newest_key_id);

		if (index === undefined) {
			index = 0;
		}

		return this.user_data.user_keys[index];
	}

	public getNewestPublicKey()
	{
		return this.getNewestKey().public_key;
	}

	public getNewestSignKey()
	{
		return this.getNewestKey().sign_key;
	}

	getSignKey(): Promise<string>
	{
		return Promise.resolve(this.getNewestSignKey());
	}

	getSignKeySync(): string
	{
		return this.getNewestSignKey();
	}

	public enabledMfa(): boolean
	{
		return this.user_data.mfa;
	}

	public async decryptHmacKeys(fetchedKeys: GroupOutDataHmacKeys[])
	{
		const keys: string[] = [];

		for (let i = 0; i < fetchedKeys.length; i++) {
			const fetched_key = fetchedKeys[i];

			// eslint-disable-next-line no-await-in-loop
			const group_key = await this.getUserSymKey(fetched_key.group_key_id);

			const decrypted_hmac_key = groupDecryptHmacKey(group_key, fetched_key.key_data);

			keys.push(decrypted_hmac_key);
		}

		return keys;
	}

	public async fetchUserKey(key_id: string, first = false)
	{
		const jwt = await this.getJwt();

		const fetched_keys = await fetchUserKey(this.base_url, this.app_token, jwt, key_id, this.user_data.device.private_key);

		const user_keys: UserKeyData = {
			exported_verify_key: fetched_keys.exportedVerifyKey,
			group_key_id: fetched_keys.groupKeyId,
			verify_key: fetched_keys.verifyKey,
			time: +fetched_keys.time,
			sign_key: fetched_keys.signKey,
			public_key: fetched_keys.publicKey,
			exported_public_key_sig_key_id: fetched_keys.exportedPublicKeySigKeyId,
			exported_public_key: fetched_keys.exportedPublicKey,
			group_key: fetched_keys.groupKey,
			private_key: fetched_keys.privateKey
		};

		const index = this.user_data.user_keys.length;
		this.user_data.user_keys.push(user_keys);

		this.user_data.key_map.set(user_keys.group_key_id, index);
		
		if (first) {
			this.user_data.newest_key_id = user_keys.group_key_id;
		}
		
		return setUserStorageData(this.user_data, this.userIdentifier);
	}

	public async getJwt()
	{
		const jwt_data = decodeJwt(this.user_data.jwt);

		const exp = jwt_data.exp;

		if (exp <= Date.now() / 1000 + 30) {
			//refresh even when the jwt is valid for 30 sec
			//update the user data to safe the updated values, we don't need the class here
			this.user_data.jwt = await Sentc.refreshJwt(this.user_data.jwt, this.user_data.refresh_token);

			//save the user data with the new jwt
			await setUserStorageData(this.user_data, this.userIdentifier);
		}

		return this.user_data.jwt;
	}

	private getFreshJwt(username: string, password: string, mfa_token?: string, mfa_recovery?: boolean)
	{
		return getFreshJwt(
			this.base_url,
			this.app_token,
			username,
			password,
			mfa_token,
			mfa_recovery
		);
	}

	public async updateUser(newIdentifier: string)
	{
		const jwt = await this.getJwt();
		return updateUser(this.base_url, this.app_token, jwt, newIdentifier);
	}

	public async registerRawOtp(password: string, mfa_token?: string, mfa_recovery?: boolean): Promise<OtpRegister>
	{
		const fresh_jwt = await this.getFreshJwt(this.userIdentifier, password, mfa_token, mfa_recovery);

		const out = await registerRawOtp(this.base_url, this.app_token, fresh_jwt);

		this.user_data.mfa = true;

		await setUserStorageData(this.user_data, this.userIdentifier);

		return out;
	}

	public async registerOtp(issuer: string, audience: string, password: string, mfa_token?: string, mfa_recovery?: boolean): Promise<[string, string[]]>
	{
		const fresh_jwt = await this.getFreshJwt(this.userIdentifier, password, mfa_token, mfa_recovery);

		const out = await registerOtp(this.base_url, this.app_token, fresh_jwt, issuer, audience);

		this.user_data.mfa = true;

		await setUserStorageData(this.user_data, this.userIdentifier);

		return [out.url, out.recover];
	}

	public async getOtpRecoverKeys(password: string, mfa_token?: string, mfa_recovery?: boolean)
	{
		const fresh_jwt = await this.getFreshJwt(this.userIdentifier, password, mfa_token, mfa_recovery);

		const out = await getOtpRecoverKeys(this.base_url, this.app_token, fresh_jwt);

		return out.keys;
	}

	public async resetRawOtp(password: string, mfa_token?: string, mfa_recovery?: boolean): Promise<OtpRegister>
	{
		const fresh_jwt = await this.getFreshJwt(this.userIdentifier, password, mfa_token, mfa_recovery);

		return resetRawOtp(this.base_url, this.app_token, fresh_jwt);
	}

	public async resetOtp(issuer: string, audience: string, password: string, mfa_token?: string, mfa_recovery?: boolean): Promise<[string, string[]]>
	{
		const fresh_jwt = await this.getFreshJwt(this.userIdentifier, password, mfa_token, mfa_recovery);

		const out = await resetOtp(this.base_url, this.app_token, fresh_jwt, issuer, audience);

		return [out.url, out.recover];
	}

	public async disableOtp(password: string, mfa_token?: string, mfa_recovery?: boolean)
	{
		const fresh_jwt = await this.getFreshJwt(this.userIdentifier, password, mfa_token, mfa_recovery);

		await disableOtp(this.base_url, this.app_token, fresh_jwt);

		this.user_data.mfa = false;
		return setUserStorageData(this.user_data, this.userIdentifier);
	}

	public async resetPassword(newPassword: string)
	{
		//check if the user is logged in with a valid jwt and got the private keys

		const jwt = await this.getJwt();

		const decryptedPrivateKey = this.user_data.device.private_key;
		const decryptedSignKey = this.user_data.device.sign_key;

		return resetPassword(
			this.base_url,
			this.app_token,
			jwt,
			newPassword,
			decryptedPrivateKey,
			decryptedSignKey
		);
	}

	public changePassword(oldPassword:string, newPassword:string, mfa_token?: string, mfa_recovery?: boolean)
	{
		if (this.user_data.mfa && !mfa_token) {
			throw create_error("client_10000", "The user enabled mfa. To change the password, the user must also enter the mfa token");
		}

		return changePassword(
			this.base_url,
			this.app_token,
			this.userIdentifier,
			oldPassword,
			newPassword,
			mfa_token,
			mfa_recovery
		);
	}

	public async logOut()
	{
		const storage = await Sentc.getStore();

		return storage.delete(USER_KEY_STORAGE_NAMES.userData + "_id_" + this.userIdentifier);
	}

	public async deleteUser(password: string, mfa_token?: string, mfa_recovery?: boolean)
	{
		if (this.user_data.mfa && !mfa_token) {
			throw create_error("client_10000", "The user enabled mfa. To delete the user, the user must also enter the mfa token");
		}

		const fresh_jwt = await this.getFreshJwt(this.userIdentifier, password, mfa_token, mfa_recovery);

		await deleteUser(this.base_url, this.app_token, fresh_jwt);

		return this.logOut();
	}

	public async deleteDevice(password: string, device_id: string, mfa_token?: string, mfa_recovery?: boolean)
	{
		if (this.user_data.mfa && !mfa_token) {
			throw create_error("client_10000", "The user enabled mfa. To delete a device, the user must also enter the mfa token");
		}

		const fresh_jwt = await this.getFreshJwt(this.userIdentifier, password, mfa_token, mfa_recovery);

		await deleteDevice(this.base_url, this.app_token, fresh_jwt, device_id);

		if (device_id === this.user_data.device_id) {
			//only log the device out if it is the actual used device
			return this.logOut();
		}
	}

	//__________________________________________________________________________________________________________________

	public prepareRegisterDevice(server_output: string, page = 0)
	{
		const key_count = this.user_data.user_keys.length;

		const [key_string] = prepareKeys(this.user_data.user_keys, page);

		return prepareRegisterDevice(server_output, key_string, key_count);
	}

	public async registerDevice(server_output: string)
	{
		const key_count = this.user_data.user_keys.length;
		const [key_string] = prepareKeys(this.user_data.user_keys);

		const jwt = await this.getJwt();

		const out = await registerDevice(this.base_url, this.app_token, jwt, server_output, key_count, key_string);
		const session_id = out.sessionId;
		const public_key = out.exportedPublicKey;

		if (session_id === "") {
			return;
		}

		let next_page = true;
		let i = 1;
		const p = [];

		while (next_page) {
			const next_keys = prepareKeys(this.user_data.user_keys, i);
			next_page = next_keys[1];

			p.push(userDeviceKeySessionUpload(this.base_url, this.app_token, jwt, session_id, public_key, next_keys[0]));

			i++;
		}

		return Promise.allSettled(p);
	}

	public async getDevices(last_fetched_item: UserDeviceList | null = null): Promise<UserDeviceList[]>
	{
		const jwt = await this.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.device_id ?? "none";

		const out = await getUserDevices(this.base_url, this.app_token, jwt, last_fetched_time, last_id);

		const arr: UserDeviceList[] = [];

		for (let i = 0; i < out.length; i++) {
			const device = out[i];

			arr.push({
				device_id: device.deviceId,
				time: +device.time,
				device_identifier: device.deviceIdentifier
			});
		}

		return arr;
	}

	public async createSafetyNumber(user_to_compare?: {user_id: string, verify_key_id: string})
	{
		let verify_key_2: string | undefined;

		if (user_to_compare) {
			verify_key_2 = await Sentc.getUserVerifyKeyData(this.base_url, this.app_token, user_to_compare.user_id, user_to_compare.verify_key_id);
		}

		return userCreateSafetyNumber(this.getNewestKey().exported_verify_key, this.user_data.user_id, verify_key_2, user_to_compare?.user_id);
	}

	//__________________________________________________________________________________________________________________

	public async keyRotation()
	{
		const jwt = await this.getJwt();

		const key_id = await userKeyRotation(this.base_url, this.app_token, jwt, this.user_data.device.public_key, this.getNewestKey().group_key);

		return this.fetchUserKey(key_id, true);
	}

	public async finishKeyRotation()
	{
		const jwt = await this.getJwt();

		let keys: GroupKeyRotationOut[] = [];

		const out = await userPreDoneKeyRotation(this.base_url, this.app_token, jwt);

		for (let i = 0; i < out.length; i++) {
			const key = out[i];

			keys.push({
				encrypted_eph_key_key_id: key.encryptedEphKeyKeyId,
				new_group_key_id: key.newGroupKeyId,
				pre_group_key_id: key.preGroupKeyId,
				server_output: key.serverOutput
			});
		}

		let next_round = false;
		let rounds_left = 10;

		const public_key = this.user_data.device.public_key;
		const private_key = this.user_data.device.private_key;

		do {
			const left_keys = [];

			for (let i = 0; i < keys.length; i++) {
				const key = keys[i];

				let pre_key: UserKeyData | undefined;

				try {
					// eslint-disable-next-line no-await-in-loop
					pre_key = await this.getUserKeys(key.pre_group_key_id);
				} catch (e) {
					//key isn't found, try next round
				}

				if (pre_key === undefined) {
					left_keys.push(key);
					continue;
				}

				// eslint-disable-next-line no-await-in-loop
				await userFinishKeyRotation(this.base_url, this.app_token, jwt, key.server_output, pre_key.group_key, public_key, private_key);

				// eslint-disable-next-line no-await-in-loop
				await this.getUserKeys(key.new_group_key_id, true);
			}

			rounds_left--;

			if (left_keys.length > 0) {
				keys = [];
				//push the not found keys into the key array, maybe the pre-group keys are in the next round
				keys.push(...left_keys);

				next_round = true;
			} else {
				next_round = false;
			}
		} while (next_round && rounds_left > 0);
	}

	//__________________________________________________________________________________________________________________

	public async getGroups(last_fetched_item: GroupList | null = null): Promise<GroupList[]>
	{
		const jwt = await this.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.group_id ?? "none";

		const out = await groupGetGroupsForUser(this.base_url, this.app_token, jwt, last_fetched_time, last_id);

		const arr: GroupList[] = [];
		for (let i = 0; i < out.length; i++) {
			const group = out[i];

			arr.push({
				group_id: group.groupId,
				time: +group.time,
				rank: group.rank,
				parent: group.parent,
				joined_time: +group.joinedTime
			});
		}

		return arr;
	}

	public async getGroupInvites(last_fetched_item: GroupInviteListItem | null = null): Promise<GroupInviteListItem[]>
	{
		const jwt = await this.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.group_id ?? "none";

		const out = await groupGetInvitesForUser(this.base_url, this.app_token, jwt, last_fetched_time, last_id);

		const arr: GroupInviteListItem[] = [];
		for (let i = 0; i < out.length; i++) {
			const group = out[i];
			arr.push({
				group_id: group.groupId,
				time: +group.time
			});
		}

		return arr;
	}

	public async acceptGroupInvite(group_id: string)
	{
		const jwt = await this.getJwt();

		return groupAcceptInvite(this.base_url, this.app_token, jwt, group_id);
	}

	public async rejectGroupInvite(group_id: string)
	{
		const jwt = await this.getJwt();

		return groupRejectInvite(this.base_url, this.app_token, jwt, group_id);
	}

	//join req
	public async groupJoinRequest(group_id: string)
	{
		const jwt = await this.getJwt();

		return groupJoinReq(this.base_url, this.app_token, jwt, group_id, "");
	}

	public async sentJoinReq(last_fetched_item: GroupInviteListItem | null = null): Promise<GroupInviteListItem[]>
	{
		const jwt = await this.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.group_id ?? "none";

		const out = await groupGetSentJoinReqUser(this.base_url, this.app_token, jwt, last_fetched_time, last_id);

		const arr: GroupInviteListItem[] = [];
		for (let i = 0; i < out.length; i++) {
			const group = out[i];
			arr.push({
				group_id: group.groupId,
				time: +group.time
			});
		}

		return arr;
	}

	public async deleteJoinReq(id: string)
	{
		const jwt = await this.getJwt();

		return groupDeleteSentJoinReqUser(this.base_url, this.app_token, jwt, id);
	}

	//__________________________________________________________________________________________________________________

	public prepareGroupCreate(sign = false)
	{
		let sign_key: string;

		if (sign) {
			sign_key = this.getNewestSignKey();
		}
		
		//important use the public key, not the exported public key here!
		return groupPrepareCreateGroup(this.getNewestPublicKey(), sign_key, this.user_data.user_id);
	}

	public async createGroup(sign = false)
	{
		const jwt = await this.getJwt();

		let sign_key: string;

		if (sign) {
			sign_key = this.getNewestSignKey();
		}

		return groupCreateGroup(
			this.base_url,
			this.app_token,
			jwt,
			this.getNewestPublicKey(),
			undefined,
			sign_key,
			this.user_data.user_id
		);
	}

	public getGroup(group_id: string, group_as_member?: string, verify = 0)
	{
		return getGroup(group_id, this.base_url, this.app_token, this, false, group_as_member, verify);
	}

	//__________________________________________________________________________________________________________________

	/**
	 * Prepare the register of a file. The server input could be passed to the sentc api from your backend
	 *
	 * encrypted_file_name, key and master_key_id are only for the frontend to encrypt more data if necessary
	 *
	 * @param file
	 * @throws SentcError
	 */
	public prepareRegisterFile(file: File): Promise<FilePrepareCreateOutput>;

	/**
	 * Prepare the register of a file. The server input could be passed to the sentc api from your backend
	 *
	 * encrypted_file_name, key and master_key_id are only for the frontend to encrypt more data if necessary
	 *
	 * this file is registered for another user to open it
	 *
	 * @param file
	 * @param reply_id
	 * @throws SentcError
	 */
	public prepareRegisterFile(file: File, reply_id: string): Promise<FilePrepareCreateOutput>;

	public async prepareRegisterFile(file: File, reply_id = ""): Promise<FilePrepareCreateOutput>
	{
		const other_user = (reply_id !== "") ? reply_id : undefined;
		reply_id = (reply_id !== "") ? reply_id : this.user_data.user_id;

		const [key, encrypted_key] = await this.generateNonRegisteredKey(reply_id);

		const uploader = new Uploader(this.base_url, this.app_token, this, undefined, other_user);

		const [server_input, encrypted_file_name] =  uploader.prepareFileRegister(
			file,
			key.key,
			encrypted_key,
			key.master_key_id
		);

		return {
			server_input,
			encrypted_file_name,
			key,
			master_key_id: key.master_key_id
		};
	}

	/**
	 * Validates the sentc file register output
	 * Returns the file id
	 *
	 * @param server_output
	 */
	public doneFileRegister(server_output: string)
	{
		const uploader = new Uploader(this.base_url, this.app_token, this);

		return uploader.doneFileRegister(server_output);
	}

	/**
	 * Upload a registered file.
	 * Session id is returned from the sentc api. The rest from @prepareRegisterFile
	 *
	 */
	public uploadFile(fileHandle: FileHandle, fileSize: number, content_key: SymKey, session_id: string): Promise<void>;

	/**
	 * Upload a registered file.
	 * Session id is returned from the sentc api. The rest from @prepareRegisterFile
	 * upload the chunks signed by the creator sign key
	 *
	 */
	public uploadFile(fileHandle: FileHandle, fileSize: number, content_key: SymKey, session_id: string, sign: true): Promise<void>;

	/**
	 * Upload a registered file.
	 * Session id is returned from the sentc api. The rest from @prepareRegisterFile
	 * optionally upload the chunks signed by the creators sign key
	 * Show the upload progress of how many chunks are already uploaded
	 *
	 */
	public uploadFile(fileHandle: FileHandle, fileSize: number, content_key: SymKey, session_id: string, sign: boolean, upload_callback: (progress?: number) => void): Promise<void>;

	public uploadFile(fileHandle: FileHandle, fileSize: number, content_key: SymKey, session_id: string, sign = false, upload_callback?: (progress?: number) => void)
	{
		const uploader = new Uploader(this.base_url, this.app_token, this, undefined, undefined, upload_callback);

		return uploader.checkFileUpload(fileHandle, fileSize, content_key.key, session_id, sign);
	}

	private async getFileMetaInfo(file_id: string, downloader: Downloader, verify_key?: string): Promise<[FileMetaInformation, SymKey]>
	{
		//1. get the file info
		const file_meta = await downloader.downloadFileMetaInformation(file_id);

		//2. get the content key which was used to encrypt the file
		const key = await this.getNonRegisteredKey(
			file_meta.master_key_id,
			file_meta.encrypted_key
		);

		//3. get the file name if any
		if (file_meta.encrypted_file_name && file_meta.encrypted_file_name !== "") {
			file_meta.file_name = key.decryptString(file_meta.encrypted_file_name, verify_key);
		}

		return [file_meta, key];
	}

	/**
	 * Get the FileMetaInformation, which contains all Information about the file
	 * Return also the file key back.
	 *
	 * This function can be used if the user needs the decrypted file name.
	 *
	 * @param file_id
	 */
	public downloadFileMetaInfo(file_id: string): Promise<[FileMetaInformation, SymKey]>;

	/**
	 * The same but with a verify-key
	 *
	 * @param file_id
	 * @param verify_key
	 */
	public downloadFileMetaInfo(file_id: string, verify_key: string): Promise<[FileMetaInformation, SymKey]>;

	public downloadFileMetaInfo(file_id: string, verify_key?: string)
	{
		const downloader = new Downloader(this.base_url, this.app_token, this);

		return this.getFileMetaInfo(file_id, downloader, verify_key);
	}

	/**
	 * Download a file but with already downloaded file information and
	 * the file key to not fetch the info and the key again.
	 *
	 * This function can be used after the downloadFileMetaInfo function
	 *
	 */
	public downloadFileWithMetaInfo(fileHandle: FileHandle, key: SymKey, file_meta: FileMetaInformation): Promise<void>;

	/**
	 * The same but with a verify-key to verify each file part
	 *
	 */
	public downloadFileWithMetaInfo(fileHandle: FileHandle, key: SymKey, file_meta: FileMetaInformation, verify_key: string): Promise<void>;

	/**
	 * The same but with optional verify key and a function to show the download progress
	 *
	 */
	public downloadFileWithMetaInfo(fileHandle: FileHandle, key: SymKey, file_meta: FileMetaInformation, verify_key: string, updateProgressCb: (progress: number) => void): Promise<void>;

	public downloadFileWithMetaInfo(fileHandle: FileHandle, key: SymKey, file_meta: FileMetaInformation, verify_key?: string, updateProgressCb?: (progress: number) => void)
	{
		const downloader = new Downloader(this.base_url, this.app_token, this);

		return downloader.downloadFileParts(fileHandle, file_meta.part_list, key.key, updateProgressCb, verify_key);
	}

	//__________________________________________________________________________________________________________________

	/**
	 * Register and upload a file to the sentc api.
	 * The file will be encrypted
	 *
	 */
	public createFile(file: FileHandle, file_name: string): Promise<FileCreateOutput>;

	/**
	 * Create a file and sign each file part with the sign key of the creator
	 *
	 */
	public createFile(file: FileHandle, file_name: string, sign: true): Promise<FileCreateOutput>;

	public createFile(file: FileHandle, file_name: string, sign: boolean, reply_id: string): Promise<FileCreateOutput>;

	/**
	 * The same but with optional signing and a function to show the upload progress
	 *
	 */
	public createFile(file: FileHandle, file_name: string, sign: boolean, reply_id: string, upload_callback: (progress?: number) => void): Promise<FileCreateOutput>;

	public async createFile(file: FileHandle, file_name: string, sign = false, reply_id = "", upload_callback?: (progress?: number) => void)
	{
		const other_user = (reply_id !== "") ? reply_id : undefined;
		reply_id = (reply_id !== "") ? reply_id : this.user_data.user_id;

		//1st register a new key for this file
		const [key, encrypted_key] = await this.generateNonRegisteredKey(reply_id);

		//2nd encrypt and upload the file, use the created key
		const uploader = new Uploader(this.base_url, this.app_token, this, undefined, other_user, upload_callback);

		const [file_id, encrypted_file_name] = await uploader.uploadFile(
			file,
			file_name,
			key.key,
			encrypted_key,
			key.master_key_id,
			sign
		);

		return {
			file_id,
			master_key_id: key.master_key_id,
			encrypted_file_name
		};
	}

	/**
	 * Register and upload a file to the sentc api.
	 * The file will be encrypted
	 *
	 */
	public createFileWithPath(path: string): Promise<FileCreateOutput>;

	/**
	 * Create a file and sign each file part with the sign key of the creator
	 *
	 */
	public createFileWithPath(path: string, sign: true): Promise<FileCreateOutput>;

	public createFileWithPath(path: string, sign: boolean, reply_id: string): Promise<FileCreateOutput>;

	public async createFileWithPath(path: string, sign = false, reply_id = "", upload_callback?: (progress?: number) => void)
	{
		const other_user = (reply_id !== "") ? reply_id : undefined;
		reply_id = (reply_id !== "") ? reply_id : this.user_data.user_id;

		//1st register a new key for this file
		const [key, encrypted_key] = await this.generateNonRegisteredKey(reply_id);

		//2nd encrypt and upload the file, use the created key
		const uploader = new Uploader(this.base_url, this.app_token, this, undefined, other_user, upload_callback);

		const [file_id, encrypted_file_name] = await uploader.uploadFileWithPath(
			path,
			key.key,
			encrypted_key,
			key.master_key_id,
			sign
		);

		return {
			file_id,
			master_key_id: key.master_key_id,
			encrypted_file_name
		};
	}

	/**
	 * Download a file. THis function will also download the file meta-information before
	 *
	 */
	public downloadFile(file_path: string, file_id: string): Promise<[FileMetaInformation, SymKey]>;

	/**
	 * The same but with a verify-key of the file creator
	 *
	 */
	public downloadFile(file_path: string, file_id: string, verify_key: string): Promise<[FileMetaInformation, SymKey]>;

	/**
	 * The same but with an optional verify-key and a function to show the download progress
	 *
	 */
	public downloadFile(file_path: string, file_id: string, verify_key: string, updateProgressCb: (progress: number) => void): Promise<[FileMetaInformation, SymKey]>;

	public async downloadFile(file_path: string, file_id: string, verify_key?: string, updateProgressCb?: (progress: number) => void)
	{
		const downloader = new Downloader(this.base_url, this.app_token, this);

		const [file_meta, key] = await this.getFileMetaInfo(file_id, downloader, verify_key);

		const file_name = await findAvailableFileName(path.join(file_path, file_meta.file_name));

		if (!file_name) {
			throw new Error("Could not find a file name");
		}

		await downloader.downloadFilePartsWithPath(file_name, file_meta.part_list, key.key, updateProgressCb, verify_key);

		return [
			file_meta,
			key
		];
	}

	public async updateFileName(file_id: string, content_key: SymKey, file_name?: string)
	{
		const jwt = await this.getJwt();

		return fileFileNameUpdate(this.base_url, this.app_token, jwt, file_id, content_key.key, file_name);
	}

	public async deleteFile(file_id: string)
	{
		const jwt = await this.getJwt();

		return fileDeleteFile(this.base_url, this.app_token, jwt, file_id);
	}
}