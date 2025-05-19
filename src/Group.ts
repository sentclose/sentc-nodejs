/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/12
 */
import {
	FileCreateOutput,
	FileMetaInformation,
	FilePrepareCreateOutput,
	GroupData,
	GroupJoinReqListItem,
	GroupKey,
	GroupKeyRotationOut,
	GroupOutDataHmacKeys,
	GroupOutDataKeys, GroupOutDataSortableKeys,
	GroupUserListItem,
	USER_KEY_STORAGE_NAMES,
	UserKeyData
} from "./Enities";
import {Sentc} from "./Sentc";
import {AbstractSymCrypto} from "./crypto/AbstractSymCrypto";
import {User} from "./User";
import {Downloader, findAvailableFileName, Uploader} from "./file";
import {SymKey} from ".";
import {
	create_error,
	GroupChildrenListItem,
	SentcError,
	GroupList,
	GroupInviteListItem
} from "@sentclose/sentc-common";
import {
	createSearchable,
	createSearchableRaw,
	fileDeleteFile,
	groupAcceptInvite,
	groupAcceptJoinReq,
	groupCreateChildGroup,
	groupCreateConnectedGroup,
	groupDecryptHmacKey,
	groupDecryptKey,
	groupDecryptSortableKey,
	groupDeleteGroup, groupDeleteSentJoinReq, groupFinishKeyRotation,
	groupGetAllFirstLevelChildren,
	groupGetGroupData,
	groupGetGroupKey,
	groupGetGroupKeys, groupGetGroupsForUser,
	groupGetGroupUpdates, groupGetInvitesForUser,
	groupGetJoinReqs,
	groupGetMember, groupGetSentJoinReq,
	groupInviteUser,
	groupInviteUserSession, groupJoinReq,
	groupJoinUserSession,
	groupKeyRotation, groupKickUser,
	groupPreDoneKeyRotation,
	groupPrepareCreateGroup,
	groupPrepareKeyRotation,
	groupPrepareKeysForNewMember, groupPrepareUpdateRank, groupRejectInvite,
	groupRejectJoinReq,
	groupStopGroupInvites, groupUpdateRank,
	leaveGroup, search, sortableEncryptNumber, sortableEncryptRawNumber, sortableEncryptRawString, sortableEncryptString
} from "@sentclose/sentc_node_js";
import {FileHandle} from "node:fs/promises";
import * as path from "path";

export function prepareKeys(keys: GroupKey[] | UserKeyData[], page = 0): [string, boolean]
{
	const offset = page * 50;
	const end = offset + 50;

	const key_slice = keys.slice(offset, end);

	let str = "[";

	for (let i = 0; i < key_slice.length; i++) {
		const key = keys[i].group_key;

		str += key + ",";
	}

	//remove the trailing comma
	str = str.slice(0, -1);

	str += "]";

	//it must be this string: [{"Aes":{"key":"D29y+nli2g4wn1GawdVmeGyo+W8HKc1cllkzqdEA2bA=","key_id":"123"}}]
	
	return [str, end < keys.length - 1];
}

/**
 * Get a group, from the storage or the server
 *
 */
export async function getGroup(
	group_id: string,
	base_url: string,
	app_token: string,
	user: User,
	parent = false,
	group_as_member?: string,
	verify = 0,
	rek = false
) {
	const storage = await Sentc.getStore();

	let user_id: string;

	if (!group_as_member || group_as_member === "") {
		user_id = user.user_data.user_id;
	} else {
		user_id = group_as_member;
	}

	const group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + user_id + "_id_" + group_id;

	const group = await storage.getItem<GroupData>(group_key);

	const jwt = await user.getJwt();

	if (group) {
		if (group.last_check_time + 60000 * 5 < Date.now()) {
			//check this every 5 min
			const update = await groupGetGroupUpdates(base_url, app_token, jwt, group_as_member);

			group.rank = update.rank;
			group.key_update = update.keyUpdate;
			group.last_check_time = Date.now();

			//update the group data in the storage
			await storage.set(group_key, group);
		}

		return new Group(group, base_url, app_token, user);
	}

	const out = await groupGetGroupData(base_url, app_token, jwt, group_id, group_as_member);

	//save the fetched keys but only decrypt them when creating the group obj
	const fetched_keys: GroupOutDataKeys[] = [];

	for (let i = 0; i < out.keys.length; i++) {
		const k = out.keys[i];
		fetched_keys.push({
			key_data: k.keyData,
			private_key_id: k.privateKeyId,
			signed_by_user_id: k.signedByUserId,
			signed_by_user_sign_key_id: k.signedByUserSignKeyId
		});
	}

	//check parent or group as member access if the groups are already fetched
	const access_by_parent_group = out.accessByParentGroup;
	const access_by_group_as_member = out.accessByGroupAsMember;

	const parent_group_id = out.parentGroupId;

	if (access_by_group_as_member && access_by_group_as_member !== "") {
		//only load the group once even for rek. calls.
		// otherwise, when access_by_parent_group is also set, this group will be checked again when loading the parent
		if (!rek) {
			//if a group as member set. load this group first to get the keys
			//no group as member flag
			await getGroup(access_by_group_as_member, base_url, app_token, user, false, undefined, verify);
		}
	}

	if (access_by_parent_group) {
		parent = true;
		//check if the parent group is fetched
		//rec here because the user might be in a parent of the parent group or so
		//check the tree until we found the group where the user accesses by user
		await getGroup(parent_group_id, base_url, app_token, user, false, group_as_member, verify, true);
	}

	let group_data: GroupData = {
		group_id: out.groupId,
		parent_group_id,
		from_parent: parent,
		rank: out.rank,
		key_update: out.keyUpdate,
		create_time: out.createdTime,
		joined_time: out.joinedTime,
		keys: [],
		key_map: new Map(),
		newest_key_id: "",
		access_by_group_as_member,
		access_by_parent_group,
		is_connected_group: out.isConnectedGroup,
		hmac_keys: [],
		sortable_keys: [],
		last_check_time: Date.now()
	};

	const group_obj = new Group(group_data, base_url, app_token, user);

	//update the group obj and the group data (which we saved in store) with the decrypted keys.
	//it is ok to use the private key with an empty array,
	// because we are using the keys of the parent group when this is a child group
	const keys = await group_obj.decryptKey(fetched_keys, verify);
	group_data.keys = keys;
	group_obj.groupKeys = keys;

	const key_map: Map<string, number> = new Map();

	//get the newest key
	const newest_key_id = keys[0].group_key_id;

	//insert in the key map
	for (let i = 0; i < keys.length; i++) {
		key_map.set(keys[i].group_key_id, i);
	}
	group_data.key_map = key_map;
	group_data.newest_key_id = newest_key_id;
	group_obj.groupKeyMap = key_map;
	group_obj.data.newest_key_id = newest_key_id;

	if (keys.length >= 50) {
		//fetch the rest of the keys via pagination, get the updated data back
		group_data = await group_obj.fetchKeys(jwt, verify);
	}

	//now decrypt the hmac key for searchable encryption, the right key must be fetched before
	const hmac_keys: GroupOutDataHmacKeys[] = [];
	for (let i = 0; i < out.hmacKeys.length; i++) {
		const k = out.hmacKeys[i];
		hmac_keys.push({
			key_data: k.keyData,
			group_key_id: k.groupKeyId
		});
	}

	const decrypted_hmac_keys = await group_obj.decryptHmacKeys(hmac_keys);
	group_obj.data.hmac_keys = decrypted_hmac_keys;
	group_data.hmac_keys = decrypted_hmac_keys;

	const sortable_keys: GroupOutDataSortableKeys[] = [];
	for (let i = 0; i < out.sortableKeys.length; i++) {
		const k = out.sortableKeys[i];
		sortable_keys.push({
			key_data: k.keyData,
			group_key_id: k.groupKeyId
		});
	}

	const decrypted_sortable_keys = await group_obj.decryptSortableKeys(sortable_keys);
	group_obj.data.sortable_keys = decrypted_sortable_keys;
	group_data.sortable_keys = decrypted_sortable_keys;
	
	await Promise.all([
		//store the group data
		storage.set(group_key, group_data),
		//save always the newest public key
		storage.set(USER_KEY_STORAGE_NAMES.groupPublicKey + "_id_" + group_id, {key: keys[0].exported_public_key, id: keys[0].group_key_id})
	]);

	return group_obj;
}

export class Group extends AbstractSymCrypto
{
	constructor(public data: GroupData, base_url: string, app_token: string, private user: User) {
		super(base_url, app_token);
	}

	set groupKeys(keys: GroupKey[])
	{
		this.data.keys = keys;
	}

	set groupKeyMap(key_map: Map<string, number>)
	{
		this.data.key_map = key_map;
	}

	//__________________________________________________________________________________________________________________

	public getChildGroup(group_id: string, verify = 0)
	{
		return getGroup(group_id, this.base_url, this.app_token, this.user, true, this.data.access_by_group_as_member, verify);
	}

	public getConnectedGroup(group_id: string, verify = 0)
	{
		//access the connected group from this group
		return getGroup(group_id, this.base_url, this.app_token, this.user, false, this.data.group_id, verify);
	}

	public async getChildren(last_fetched_item: GroupChildrenListItem | null = null): Promise<GroupChildrenListItem[]>
	{
		const jwt = await this.user.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.group_id ?? "none";

		const out = await groupGetAllFirstLevelChildren(this.base_url, this.app_token, jwt, this.data.group_id, last_fetched_time, last_id, this.data.access_by_group_as_member);

		const list: GroupChildrenListItem[] = [];
		for (let i = 0; i < out.length; i++) {
			const k = out[i];
			list.push({
				group_id: k.groupId,
				time: +k.time,
				parent: k.parent
			});
		}
		
		return list;
	}

	public prepareCreateChildGroup(sign = false)
	{
		const latest_key = this.getNewestKey();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.user.getNewestSignKey();
		}

		const group_input = groupPrepareCreateGroup(
			latest_key.public_group_key,
			sign_key,
			this.user.user_data.user_id
		);

		return [group_input, latest_key.group_key_id];
	}

	public async createChildGroup(sign = false)
	{
		const latest_key = this.getNewestKey().public_group_key;

		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.user.getNewestSignKey();
		}

		const jwt = await this.user.getJwt();

		return groupCreateChildGroup(
			this.base_url,
			this.app_token,
			jwt,
			latest_key,
			this.data.group_id,
			this.data.rank,
			this.data.access_by_group_as_member,
			sign_key,
			this.user.user_data.user_id
		);
	}

	public async createConnectedGroup(sign = false)
	{
		const latest_key = this.getNewestKey().public_group_key;

		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.user.getNewestSignKey();
		}

		const jwt = await this.user.getJwt();

		return groupCreateConnectedGroup(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			this.data.rank,
			latest_key,
			this.data.access_by_group_as_member,
			sign_key,
			this.user.user_data.user_id
		);
	}

	public async groupUpdateCheck()
	{
		const out = await groupGetGroupUpdates(this.base_url, this.app_token, await this.getJwt(), this.data.group_id, this.data.access_by_group_as_member);

		this.data.rank = out.rank;
		this.data.key_update = out.keyUpdate;
		this.data.last_check_time = Date.now();
	}

	public async getMember(last_fetched_item: GroupUserListItem | null = null): Promise<GroupUserListItem[]>
	{
		const jwt = await this.user.getJwt();

		const last_fetched_time = last_fetched_item?.joined_time.toString() ?? "0";
		const last_id = last_fetched_item?.user_id ?? "none";

		const out = await groupGetMember(this.base_url, this.app_token, jwt, this.data.group_id, last_fetched_time, last_id, this.data.access_by_group_as_member);

		const list: GroupUserListItem[] = [];

		for (let i = 0; i < out.length; i++) {
			const k = out[i];
			list.push({
				user_id: k.userId,
				rank: k.rank,
				joined_time: +k.joinedTime,
				user_type: k.userType
			});
		}

		return list;
	}

	public async stopInvites()
	{
		const jwt = await this.user.getJwt();

		return groupStopGroupInvites(this.base_url, this.app_token, jwt, this.data.group_id, this.data.rank, this.data.access_by_group_as_member);
	}

	public async prepareKeysForNewMember(user_id: string, rank?: number, page = 0, group = false)
	{
		const key_count = this.data.keys.length;

		let public_key: string;

		if (group) {
			const k = await Sentc.getGroupPublicKeyData(this.base_url, this.app_token, user_id);
			public_key = k.key;
		} else {
			const k = await Sentc.getUserPublicKeyData(this.base_url, this.app_token, user_id);
			public_key = k.public_key;
		}

		const [key_string] = this.prepareKeys(page);

		return groupPrepareKeysForNewMember(public_key, key_string, key_count, rank, this.data.rank);
	}

	public async handleInviteSessionKeysForNewMember(session_id: string, user_id: string, auto = false, group = false)
	{
		if (session_id === "") {
			return;
		}

		const jwt = await this.user.getJwt();

		let public_key: string;

		if (group) {
			const k = await Sentc.getGroupPublicKeyData(this.base_url, this.app_token, user_id);
			public_key = k.key;
		} else {
			const k = await Sentc.getUserPublicKeyData(this.base_url, this.app_token, user_id);
			public_key = k.public_key;
		}

		let next_page = true;
		let i = 1;
		const p = [];

		while (next_page) {
			const next_keys = this.prepareKeys(i);
			next_page = next_keys[1];

			p.push(groupInviteUserSession(
				this.base_url,
				this.app_token,
				jwt,
				this.data.group_id,
				auto,
				session_id,
				public_key,
				next_keys[0],
				this.data.access_by_group_as_member
			));

			i++;
		}

		return Promise.allSettled(p);
	}

	public invite(user_id: string, rank?: number)
	{
		return this.inviteUserInternally(user_id, rank);
	}

	public inviteAuto(user_id: string, rank?: number)
	{
		return this.inviteUserInternally(user_id, rank, true);
	}

	public inviteGroup(group_id: string, rank?: number)
	{
		return this.inviteUserInternally(group_id, rank, false, true);
	}

	public inviteGroupAuto(group_id: string, rank?: number)
	{
		return this.inviteUserInternally(group_id, rank, true, true);
	}

	public reInviteUser(user_id: string)
	{
		return this.inviteUserInternally(user_id, undefined, false, false, true);
	}

	public reInviteGroup(group_id: string)
	{
		return this.inviteUserInternally(group_id, undefined, false, true, true);
	}

	private async inviteUserInternally(user_id: string, rank?: number, auto = false, group = false, re_invite = false)
	{
		let public_key: string;

		if (group) {
			const k = await Sentc.getGroupPublicKeyData(this.base_url, this.app_token, user_id);
			public_key = k.key;
		} else {
			const k = await Sentc.getUserPublicKeyData(this.base_url, this.app_token, user_id);
			public_key = k.public_key;
		}

		const key_count = this.data.keys.length;
		const [key_string] = this.prepareKeys();

		const jwt = await this.user.getJwt();

		const session_id = await groupInviteUser(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			user_id,
			key_count,
			rank,
			this.data.rank,
			auto,
			group,
			re_invite,
			public_key,
			key_string,
			this.data.access_by_group_as_member
		);

		if (session_id === "") {
			return;
		}

		//upload the rest of the keys via session
		let next_page = true;
		let i = 1;
		const p = [];

		while (next_page) {
			const next_keys = this.prepareKeys(i);
			next_page = next_keys[1];

			p.push(groupInviteUserSession(
				this.base_url,
				this.app_token,
				jwt,
				this.data.group_id,
				auto,
				session_id,
				public_key,
				next_keys[0],
				this.data.access_by_group_as_member
			));

			i++;
		}

		return Promise.allSettled(p);
	}

	//__________________________________________________________________________________________________________________
	//join req

	public async getJoinRequests(last_fetched_item: GroupJoinReqListItem | null = null): Promise<GroupJoinReqListItem[]>
	{
		if (this.data.rank > 2) {
			throw create_error("client_201", "No permission to fulfill this action");
		}

		const jwt = await this.user.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.user_id ?? "none";

		const out = await groupGetJoinReqs(this.base_url, this.app_token, jwt, this.data.group_id, this.data.rank, last_fetched_time, last_id, this.data.access_by_group_as_member);
		const list: GroupJoinReqListItem[] = [];
		for (let i = 0; i < out.length; i++) {
			const k = out[i];
			list.push({
				user_id: k.userId,
				time: +k.time,
				user_type: k.userType
			});
		}

		return list;
	}

	public async rejectJoinRequest(user_id: string)
	{
		const jwt = await this.user.getJwt();

		return groupRejectJoinReq(this.base_url, this.app_token, jwt, this.data.group_id, this.data.rank, user_id, this.data.access_by_group_as_member);

	}

	public async acceptJoinRequest(user_id: string, user_type: 0 | 2 = 0, rank?: number)
	{
		const jwt = await this.user.getJwt();
		const key_count = this.data.keys.length;
		const [key_string] = this.prepareKeys();

		let public_key: string;

		if (user_type === 2) {
			const k = await Sentc.getGroupPublicKeyData(this.base_url, this.app_token, user_id);
			public_key = k.key;
		} else {
			const k = await Sentc.getUserPublicKeyData(this.base_url, this.app_token, user_id);
			public_key = k.public_key;
		}

		const session_id = await groupAcceptJoinReq(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			user_id,
			key_count,
			rank,
			this.data.rank,
			public_key,
			key_string,
			this.data.access_by_group_as_member
		);

		if (session_id === "") {
			return;
		}

		let next_page = true;
		let i = 1;
		const p = [];

		while (next_page) {
			const next_keys = this.prepareKeys(i);
			next_page = next_keys[1];

			p.push(groupJoinUserSession(
				this.base_url,
				this.app_token,
				jwt,
				this.data.group_id,
				session_id,
				public_key,
				next_keys[0],
				this.data.access_by_group_as_member
			));

			i++;
		}

		return Promise.allSettled(p);
	}

	//__________________________________________________________________________________________________________________

	public async leave()
	{
		const jwt = await this.user.getJwt();

		return leaveGroup(this.base_url, this.app_token, jwt, this.data.group_id, this.data.access_by_group_as_member);
	}

	//__________________________________________________________________________________________________________________
	//key rotation

	/**
	 * Get the actual used public key.
	 * For the user, or if the user joined via a parent group, the parent group public key
	 *
	 * Returns only the public key format, not the exported public key!
	 *
	 * @private
	 */
	private async getPublicKey()
	{
		//normal user access
		if (!this.data.from_parent && !this.data.access_by_group_as_member) {
			return this.user.getNewestPublicKey();
		}

		//access with parent group -> get the keys from the parent group
		//no need to change for a group as a member because we are using the keys of the parent
		if (this.data.from_parent) {
			//choose the right user id.
			// when the user is accessing the group over a parent which is also accessed by a connected group
			let user_id: string;
			if (!this.data.access_by_group_as_member) {
				user_id = this.user.user_data.user_id;
			} else {
				user_id = this.data.access_by_group_as_member;
			}

			//get parent group public key
			const storage = await Sentc.getStore();
			const parent_group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + user_id + "_id_" + this.data.parent_group_id;
			const parent_group: GroupData = await storage.getItem(parent_group_key);

			if (!parent_group) {
				throw new Error("Parent group not found. This group was access from parent group but the parent group data is gone.");
			}

			const newest_key_id = parent_group.newest_key_id;
			const index = parent_group.key_map.get(newest_key_id);

			if (index === undefined) {
				throw new Error("Parent group not found. This group was access from parent group but the parent group data is gone.");
			}

			//use the latest key
			const public_key = parent_group.keys[index]?.public_group_key;

			if (!public_key) {
				throw new Error("Parent group not found. This group was access from parent group but the parent group data is gone.");
			}

			return public_key;
		}

		//access not over parent but from group as member -> use the keys from the group as member
		const storage = await Sentc.getStore();
		const connected_group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + this.user.user_data.user_id + "_id_" + this.data.access_by_group_as_member;
		const connected_group: GroupData = await storage.getItem(connected_group_key);

		if (!connected_group) {
			throw new Error("Connected group not found. This group was access from a connected group but the group data is gone.");
		}

		const newest_key_id = connected_group.newest_key_id;
		const index = connected_group.key_map.get(newest_key_id);

		if (index === undefined) {
			throw new Error("Connected group not found. This group was access from a connected group but the group data is gone.");
		}

		//use the latest key
		const public_key = connected_group.keys[index]?.public_group_key;

		if (!public_key) {
			throw new Error("Connected group not found. This group was access from a connected group but the group data is gone.");
		}

		return public_key;
	}

	private getNewestKey()
	{
		let index = this.data.key_map.get(this.data.newest_key_id);

		if (!index) {
			index = 0;
		}

		return this.data.keys[index];
	}

	/**
	 * Gets the right private key to the used public key
	 *
	 * If it is from a user -> get it from a user
	 *
	 * If not, then form the parent group
	 *
	 * @param private_key_id
	 * @private
	 */
	private async getPrivateKey(private_key_id: string)
	{
		if (!this.data.from_parent && !this.data.access_by_group_as_member) {
			return this.user.getPrivateKey(private_key_id);
		}

		if (this.data.from_parent) {
			let user_id: string;
			if (!this.data.access_by_group_as_member) {
				user_id = this.user.user_data.user_id;
			} else {
				user_id = this.data.access_by_group_as_member;
			}

			//get parent group private key
			const storage = await Sentc.getStore();
			const parent_group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + user_id + "_id_" + this.data.parent_group_id;
			const parent_group_data: GroupData = await storage.getItem(parent_group_key);

			if (!parent_group_data) {
				throw new Error("Parent group not found. This group was access from parent group but the parent group data is gone.");
			}

			const parent_group = new Group(parent_group_data, this.base_url, this.app_token, this.user);

			//private key id got the same id as the group key
			const group_key = await parent_group.getGroupKey(private_key_id);

			//use the latest key
			return group_key.private_group_key;
		}

		//access over "group as member"
		const storage = await Sentc.getStore();
		const connected_group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + this.user.user_data.user_id + "_id_" + this.data.access_by_group_as_member;
		const connected_group_data: GroupData = await storage.getItem(connected_group_key);

		if (!connected_group_data) {
			throw new Error("Connected group not found. This group was access from a connected group but the group data is gone.");
		}

		const connected_group = new Group(connected_group_data, this.base_url, this.app_token, this.user);

		const group_key = await connected_group.getGroupKey(private_key_id);

		return group_key.private_group_key;
	}

	/**
	 * Prepares the key rotation to use it with own backend.
	 *
	 * The newest public key is used to encrypt the key for the starter.
	 * If the starter joined via a parent group, then the parent group public key is used
	 */
	public async prepareKeyRotation(sign = false)
	{
		//if this is a child group -> start the key rotation with the parent key!
		const public_key = await this.getPublicKey();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.getSignKey();
		}

		return groupPrepareKeyRotation(this.getNewestKey().group_key, public_key, sign_key, this.user.user_data.user_id);
	}

	public async keyRotation(sign = false)
	{
		const jwt = await this.user.getJwt();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.getSignKey();
		}

		const key_id = await groupKeyRotation(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			await this.getPublicKey(),
			this.getNewestKey().group_key,
			sign_key,
			this.user.user_data.user_id,
			this.data.access_by_group_as_member
		);

		return this.getGroupKey(key_id, true);
	}

	public async finishKeyRotation(verify = 0)
	{
		const jwt = await this.user.getJwt();

		let keys: GroupKeyRotationOut[] = [];

		const out = await groupPreDoneKeyRotation(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			this.data.access_by_group_as_member
		);

		for (let i = 0; i < out.length; i++) {
			const k = out[i];
			keys.push({
				pre_group_key_id: k.preGroupKeyId,
				new_group_key_id: k.newGroupKeyId,
				encrypted_eph_key_key_id: k.encryptedEphKeyKeyId,
				server_output: k.serverOutput
			});
		}

		if (keys.length === 0) {
			return; 
		}

		let next_round = false;
		let rounds_left = 10;

		//use always the newest public key
		const public_key = await this.getPublicKey();

		do {
			const left_keys = [];

			//should be always there because the group rotation keys are ordered by time
			for (let i = 0; i < keys.length; i++) {
				const key = keys[i];

				let pre_key: GroupKey;

				try {
					// eslint-disable-next-line no-await-in-loop
					pre_key = await this.getGroupKey(key.pre_group_key_id, false, verify);
					// eslint-disable-next-line no-empty
				} catch (e) {
					//the key isn't found -> try the next round
				}

				if (pre_key === undefined) {
					left_keys.push(key);
					continue;
				}

				//get the right used private key for each key
				// eslint-disable-next-line no-await-in-loop
				const private_key = await this.getPrivateKey(key.encrypted_eph_key_key_id);

				//await must be in this loop because we need the keys
				// eslint-disable-next-line no-await-in-loop
				await groupFinishKeyRotation(
					this.base_url,
					this.app_token,
					jwt,
					this.data.group_id,
					key.server_output,
					pre_key.group_key,
					public_key,
					private_key,
					this.data.access_by_group_as_member
				);
				
				//now get the new key and safe it
				// eslint-disable-next-line no-await-in-loop
				await this.getGroupKey(key.new_group_key_id, true, verify);
			}

			//when it runs 10 times and there are still left -> breakup
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

		let user_id: string;
		if (!this.data.access_by_group_as_member) {
			user_id = this.user.user_data.user_id;
		} else {
			user_id = this.data.access_by_group_as_member;
		}

		//after a key rotation -> save the new group data in the store
		const storage = await Sentc.getStore();
		const group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + user_id + "_id_" + this.data.group_id;
		return storage.set(group_key, this.data);
	}

	//__________________________________________________________________________________________________________________

	public prepareUpdateRank(user_id: string, new_rank: number)
	{
		return groupPrepareUpdateRank(user_id, new_rank, this.data.rank);
	}

	public async updateRank(user_id: string, new_rank: number)
	{
		const jwt = await this.user.getJwt();

		//check if the updated user is the actual user -> then update the group store

		await groupUpdateRank(this.base_url, this.app_token, jwt, this.data.group_id, user_id, new_rank, this.data.rank, this.data.access_by_group_as_member);
		
		let actual_user_id: string;
		if (!this.data.access_by_group_as_member) {
			actual_user_id = this.user.user_data.user_id;
		} else {
			actual_user_id = this.data.access_by_group_as_member;
		}

		if (actual_user_id === user_id) {
			const storage = await Sentc.getStore();
			const group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + actual_user_id + "_id_" + this.data.group_id;

			this.data.rank = new_rank;

			return storage.set(group_key, this.data);
		}
	}

	public async kickUser(user_id: string)
	{
		const jwt = await this.user.getJwt();

		return groupKickUser(this.base_url, this.app_token, jwt, this.data.group_id, user_id, this.data.rank, this.data.access_by_group_as_member);
	}

	//__________________________________________________________________________________________________________________
	//group as member

	public async getGroups(last_fetched_item: GroupList | null = null): Promise<GroupList[]>
	{
		const jwt = await this.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.group_id ?? "none";

		const out = await groupGetGroupsForUser(this.base_url, this.app_token, jwt, last_fetched_time, last_id, this.data.group_id);

		const list: GroupList[] = [];
		for (let i = 0; i < out.length; i++) {
			const g = out[i];
			list.push({
				group_id: g.groupId,
				rank: g.rank,
				joined_time: +g.joinedTime,
				parent: g.parent,
				time: +g.time
			});
		}

		return list;
	}

	//join req to another group to connect
	public async getGroupInvites(last_fetched_item: GroupInviteListItem | null = null): Promise<GroupInviteListItem[]>
	{
		const jwt = await this.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.group_id ?? "none";

		const out = await groupGetInvitesForUser(this.base_url, this.app_token, jwt, last_fetched_time, last_id, this.data.group_id, this.data.access_by_group_as_member);

		const list: GroupInviteListItem[] = [];
		for (let i = 0; i < out.length; i++) {
			const l = out[i];
			list.push({
				group_id: l.groupId,
				time: +l.time
			});
		}

		return list;
	}

	public async acceptGroupInvite(group_id: string)
	{
		const jwt = await this.getJwt();

		return groupAcceptInvite(this.base_url, this.app_token, jwt, group_id, this.data.group_id, this.data.access_by_group_as_member);
	}

	public async rejectGroupInvite(group_id: string)
	{
		const jwt = await this.getJwt();

		return groupRejectInvite(this.base_url, this.app_token, jwt, group_id, this.data.group_id, this.data.access_by_group_as_member);
	}

	//join req to another group
	public async groupJoinRequest(group_id: string)
	{
		const jwt = await this.getJwt();

		return groupJoinReq(this.base_url, this.app_token, jwt, group_id, this.data.group_id, this.data.access_by_group_as_member);
	}

	public async sentJoinReq(last_fetched_item: GroupInviteListItem | null = null): Promise<GroupInviteListItem[]>
	{
		const jwt = await this.user.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.group_id ?? "none";

		const out = await groupGetSentJoinReq(this.base_url, this.app_token, jwt, this.data.group_id, this.data.rank, last_fetched_time, last_id, this.data.access_by_group_as_member);
		const list: GroupInviteListItem[] = [];
		for (let i = 0; i < out.length; i++) {
			const l = out[i];
			list.push({
				group_id: l.groupId,
				time: +l.time
			});
		}

		return list;
	}

	public async deleteJoinReq(id: string)
	{
		const jwt = await this.user.getJwt();

		return groupDeleteSentJoinReq(this.base_url, this.app_token, jwt, this.data.group_id, this.data.rank, id, this.data.access_by_group_as_member);
	}

	//__________________________________________________________________________________________________________________

	public async deleteGroup()
	{
		if (this.data.rank > 1) {
			throw create_error("client_201", "No permission to fulfill this action");
		}
		
		const jwt = await this.user.getJwt();

		return groupDeleteGroup(this.base_url, this.app_token, jwt, this.data.group_id, this.data.rank, this.data.access_by_group_as_member);
	}

	//__________________________________________________________________________________________________________________

	public async fetchKeys(jwt: string, verify = 0)
	{
		let last_item = this.data.keys[this.data.keys.length - 1];

		let next_fetch = true;

		const keys: GroupKey[] = [];

		while (next_fetch) {
			
			// eslint-disable-next-line no-await-in-loop
			const out = await groupGetGroupKeys(this.base_url, this.app_token, jwt, this.data.group_id, last_item.time, last_item.group_key_id);

			const fetchedKeys: GroupOutDataKeys[] = [];
			for (let i = 0; i < out.length; i++) {
				const key = out[i];

				fetchedKeys.push({
					key_data: key.keyData,
					private_key_id: key.privateKeyId,
					signed_by_user_id: key.signedByUserId,
					signed_by_user_sign_key_id: key.signedByUserSignKeyId
				});
			}

			// eslint-disable-next-line no-await-in-loop
			const decrypted_key = await this.decryptKey(fetchedKeys, verify);

			keys.push(...decrypted_key);

			next_fetch = fetchedKeys.length >= 50;

			last_item = decrypted_key[fetchedKeys.length - 1];
		}

		const last_inserted_key_index = this.data.keys.length;

		//insert in the key map
		for (let i = 0; i < keys.length; i++) {
			this.data.key_map.set(keys[i].group_key_id, i + last_inserted_key_index);
		}

		this.data.keys.push(...keys);

		//return the updated data so it can be saved in the store
		return this.data;
	}

	/**
	 * Decrypt the key with the right private key.
	 *
	 * get the right private key for each key
	 *
	 * @param fetchedKeys
	 * @param verify
	 */
	public async decryptKey(fetchedKeys: GroupOutDataKeys[], verify = 0): Promise<GroupKey[]>
	{
		const keys: GroupKey[] = [];

		for (let i = 0; i < fetchedKeys.length; i++) {
			const fetched_key = fetchedKeys[i];

			// eslint-disable-next-line no-await-in-loop
			const private_key = await this.getPrivateKey(fetched_key.private_key_id);

			let verify_key: string | undefined;
			
			if (verify > 0 && fetched_key.signed_by_user_id && fetched_key.signed_by_user_sign_key_id) {
				try {
					// eslint-disable-next-line no-await-in-loop
					verify_key = await Sentc.getUserVerifyKeyData(this.base_url, this.app_token, fetched_key.signed_by_user_id, fetched_key.signed_by_user_sign_key_id);
				} catch (e) {
					//for "verify" = 1 ignore the error and just decrypt the key
					if (verify === 2) {
						//check if code === 100 -> user not found. if so, ignore this error and use no verify-key
						const err: SentcError = JSON.parse(e);
						if (err.status !== "server_100") {
							throw e;
						}
					}
				}
			}
			
			const decrypted_keys = groupDecryptKey(private_key, fetched_key.key_data, verify_key);

			keys.push({
				group_key_id: decrypted_keys.groupKeyId,
				group_key: decrypted_keys.groupKey,
				private_group_key: decrypted_keys.privateGroupKey,
				time: decrypted_keys.time,
				public_group_key: decrypted_keys.publicGroupKey,
				exported_public_key: decrypted_keys.exportedPublicKey
			});
		}

		return keys;
	}

	public async decryptHmacKeys(fetchedKeys: GroupOutDataHmacKeys[])
	{
		const keys = [];

		for (let i = 0; i < fetchedKeys.length; i++) {
			const fetched_key = fetchedKeys[i];

			// eslint-disable-next-line no-await-in-loop
			const group_key = await this.getSymKeyById(fetched_key.group_key_id);

			const decrypted_hmac_key = groupDecryptHmacKey(group_key, fetched_key.key_data);

			keys.push(decrypted_hmac_key);
		}

		return keys;
	}

	public async decryptSortableKeys(fetchedKeys: GroupOutDataSortableKeys[])
	{
		const keys = [];

		for (let i = 0; i < fetchedKeys.length; i++) {
			const fetched_key = fetchedKeys[i];

			// eslint-disable-next-line no-await-in-loop
			const group_key = await this.getSymKeyById(fetched_key.group_key_id);

			const decrypted_key = groupDecryptSortableKey(group_key, fetched_key.key_data);

			keys.push(decrypted_key);
		}

		return keys;
	}

	private prepareKeys(page = 0): [string, boolean]
	{
		return prepareKeys(this.data.keys, page);
	}

	private async getGroupKey(key_id: string, new_keys = false, verify = 0)
	{
		let key_index = this.data.key_map.get(key_id);

		if (key_index === undefined) {
			const jwt = await this.user.getJwt();

			const fetched_key = await groupGetGroupKey(this.base_url, this.app_token, jwt, this.data.group_id, key_id, this.data.access_by_group_as_member);

			const key: GroupOutDataKeys = {
				key_data: fetched_key.keyData,
				private_key_id: fetched_key.privateKeyId,
				signed_by_user_id: fetched_key.signedByUserId,
				signed_by_user_sign_key_id: fetched_key.signedByUserSignKeyId
			};

			const decrypted_key = await this.decryptKey([key], verify);

			const last_inserted_key_index = this.data.keys.length;
			this.data.keys.push(decrypted_key[0]);
			this.data.key_map.set(decrypted_key[0].group_key_id, last_inserted_key_index);

			const storage = await Sentc.getStore();

			if (new_keys) {
				this.data.newest_key_id = decrypted_key[0].group_key_id;

				//save also the newest key in the cache
				await storage.set(USER_KEY_STORAGE_NAMES.groupPublicKey + "_id_" + this.data.group_id, {key: decrypted_key[0].exported_public_key, id: decrypted_key[0].group_key_id});
			}

			let actual_user_id: string;
			if (!this.data.access_by_group_as_member) {
				actual_user_id = this.user.user_data.user_id;
			} else {
				actual_user_id = this.data.access_by_group_as_member;
			}

			const group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + actual_user_id + "_id_" + this.data.group_id;

			await storage.set(group_key, this.data);

			key_index = this.data.key_map.get(key_id);
			if (!key_index) {
				//key not found
				throw new Error("Group key not found. Maybe done key rotation will help");
			}
		}

		const key = this.data.keys[key_index];
		if (!key) {
			//key not found
			throw new Error("Group key not found. Maybe done key rotation will help");
		}

		return key;
	}

	private getGroupKeySync(key_id: string)
	{
		const key_index = this.data.key_map.get(key_id);

		if (key_index === undefined) {
			throw new Error("Key not found");
		}

		const key = this.data.keys[key_index];
		if (!key) {
			//key not found
			throw new Error("Group key not found. Maybe done key rotation will help");
		}

		return key;
	}

	//__________________________________________________________________________________________________________________

	getSymKeyToEncrypt(): Promise<[string, string]>
	{
		const latest_key = this.getNewestKey();

		return Promise.resolve([latest_key.group_key, latest_key.group_key_id]);
	}

	getSymKeyToEncryptSync(): [string, string]
	{
		const latest_key = this.getNewestKey();

		return [latest_key.group_key, latest_key.group_key_id];
	}

	async getSymKeyById(key_id: string): Promise<string>
	{
		const key = await this.getGroupKey(key_id);

		return key.group_key;
	}

	getSymKeyByIdSync(key_id: string): string
	{
		const key = this.getGroupKeySync(key_id);

		return key.group_key;
	}

	getJwt(): Promise<string>
	{
		return this.user.getJwt();
	}

	getSignKey(): Promise<string>
	{
		//always use the users sign key
		return this.user.getSignKey();
	}

	getSignKeySync(): string
	{
		return this.user.getSignKeySync();
	}

	getNewestHmacKey(): string
	{
		return this.data.hmac_keys[0];
	}

	getNewestSortableKey(): string
	{
		return this.data.sortable_keys[0];
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
	public async prepareRegisterFile(file: File): Promise<FilePrepareCreateOutput>
	{
		const [key, encrypted_key] = await this.generateNonRegisteredKey();

		const uploader = new Uploader(this.base_url, this.app_token, this.user, this.data.group_id, this.data.access_by_group_as_member);

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
		const uploader = new Uploader(this.base_url, this.app_token, this.user, this.data.group_id, this.data.access_by_group_as_member);

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
		//call this after "file register"
		const uploader = new Uploader(this.base_url, this.app_token, this.user, this.data.group_id, undefined, upload_callback, this.data.access_by_group_as_member);

		return uploader.checkFileUpload(fileHandle, fileSize, content_key.key, session_id, sign);
	}

	private async getFileMetaInfo(file_id: string, downloader: Downloader, verify_key?: string): Promise<[FileMetaInformation, SymKey]>
	{
		//in an extra function to use the downloader

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
		const downloader = new Downloader(this.base_url, this.app_token, this.user, this.data.group_id, this.data.access_by_group_as_member);

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
		const downloader = new Downloader(this.base_url, this.app_token, this.user, this.data.group_id, this.data.access_by_group_as_member);

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

	/**
	 * The same but with optional signing and a function to show the upload progress
	 *
	 */
	public createFile(file: FileHandle, file_name: string, sign: boolean, upload_callback: (progress?: number) => void): Promise<FileCreateOutput>;

	public async createFile(file: FileHandle, file_name: string, sign = false, upload_callback?: (progress?: number) => void)
	{
		//1st register a new key for this file
		const [key, encrypted_key] = await this.generateNonRegisteredKey();

		//2nd encrypt and upload the file, use the created key
		const uploader = new Uploader(
			this.base_url,
			this.app_token,
			this.user,
			this.data.group_id,
			undefined,
			upload_callback,
			this.data.access_by_group_as_member
		);

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

	/**
	 * The same but with optional signing and a function to show the upload progress
	 *
	 */
	public createFileWithPath(path: string, sign: boolean, upload_callback: (progress?: number) => void): Promise<FileCreateOutput>;


	public async createFileWithPath(path: string, sign = false, upload_callback?: (progress?: number) => void)
	{
		//1st register a new key for this file
		const [key, encrypted_key] = await this.generateNonRegisteredKey();

		//2nd encrypt and upload the file, use the created key
		const uploader = new Uploader(
			this.base_url,
			this.app_token,
			this.user,
			this.data.group_id,
			undefined,
			upload_callback,
			this.data.access_by_group_as_member
		);

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
		const downloader = new Downloader(this.base_url, this.app_token, this.user, this.data.group_id, this.data.access_by_group_as_member);

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

	/**
	 * Delete a file at the backend. Only creator or group admin can delete files
	 *
	 * @param file_id
	 */
	public async deleteFile(file_id: string)
	{
		const jwt = await this.getJwt();

		return fileDeleteFile(this.base_url, this.app_token, jwt,  file_id, this.data.group_id, this.data.access_by_group_as_member);
	}

	//__________________________________________________________________________________________________________________
	//searchable encryption

	public createSearchRaw(data: string, full?: boolean, limit?: number): string[]
	{
		const key = this.getNewestHmacKey();

		return createSearchableRaw(key, data, full === undefined ? false : full, limit);
	}

	public createSearch(data: string, full?: boolean, limit?: number): [string[], string, string]
	{
		const key = this.getNewestHmacKey();
		
		const out = createSearchable(key, data, full === undefined ? false : full, limit);

		return [out.hashes, out.alg, out.keyId];
	}

	public search(data: string): string
	{
		const key = this.getNewestHmacKey();
		
		return search(key, data);
	}

	//__________________________________________________________________________________________________________________
	//sortable

	public encryptSortableRawNumber(number: number)
	{
		const key = this.getNewestSortableKey();

		return sortableEncryptRawNumber(key, number);
	}

	public encryptSortableNumber(number: number): [number, string, string]
	{
		const key = this.getNewestSortableKey();

		const out = sortableEncryptNumber(key, number);

		return [out.number, out.alg, out.keyId];
	}

	public encryptSortableRawString(data: string)
	{
		const key = this.getNewestSortableKey();

		return sortableEncryptRawString(key, data);
	}
	
	public encryptSortableString(data: string): [number, string, string]
	{
		const key = this.getNewestSortableKey();

		const out = sortableEncryptString(key, data);

		return [out.number, out.alg, out.keyId];
	}
}
