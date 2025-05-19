/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/19
 */
import {AbstractCrypto} from "./AbstractCrypto";
import {CryptoHead, CryptoRawOutput, UserPublicKeyData} from "../Enities";
import {getNonRegisteredKeyByPrivateKey, SymKey} from "./SymKey";
import {Sentc} from "../Sentc";
import {
	decryptAsymmetric,
	decryptRawAsymmetric,
	decryptStringAsymmetric,
	deserializeHeadFromString,
	encryptAsymmetric,
	encryptRawAsymmetric,
	encryptStringAsymmetric,
	generateNonRegisterSymKeyByPublicKey,
	splitHeadAndEncryptedData,
	splitHeadAndEncryptedString
} from "@sentclose/sentc_node_js";

export abstract class AbstractAsymCrypto extends AbstractCrypto
{
	/**
	 * Fetch the public key for this user
	 *
	 * @param reply_id
	 */
	abstract getPublicKey(reply_id: string): Promise<UserPublicKeyData>;

	/**
	 * Get the own private key
	 * because only the actual user got access to the private key
	 *
	 * @param key_id
	 */
	abstract getPrivateKey(key_id: string): Promise<string>;

	abstract getPrivateKeySync(key_id: string): string;

	abstract getSignKey(): Promise<string>;

	abstract getSignKeySync(): string;

	abstract getJwt(): Promise<string>;

	public encryptRaw(data: Buffer, reply_id: string): Promise<CryptoRawOutput>;

	public encryptRaw(data: Buffer, reply_id: string, sign: true): Promise<CryptoRawOutput>;

	public async encryptRaw(data: Buffer, reply_id: string, sign = false): Promise<CryptoRawOutput>
	{
		const key = await this.getPublicKey(reply_id);

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.getSignKey();
		}

		const out = encryptRawAsymmetric(key.public_key, data, sign_key);

		return {
			head: out.head,
			data: out.data
		};
	}

	public encryptRawSync(data: Buffer, reply_public_key: string, sign = false): CryptoRawOutput
	{
		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.getSignKeySync();
		}

		const out = encryptRawAsymmetric(reply_public_key, data, sign_key);

		return {
			head: out.head,
			data: out.data
		};
	}

	public decryptRaw(head: string, encrypted_data: Buffer): Promise<Buffer>;

	public decryptRaw(head: string, encrypted_data: Buffer, verify_key: string): Promise<Buffer>;

	public async decryptRaw(head: string, encrypted_data: Buffer, verify_key?: string): Promise<Buffer>
	{
		const de_head: CryptoHead = deserializeHeadFromString(head);

		const key = await this.getPrivateKey(de_head.id);

		return decryptRawAsymmetric(key, encrypted_data, head, verify_key);
	}

	public decryptRawSync(head: string, encrypted_data: Buffer, verify_key?: string)
	{
		const de_head: CryptoHead = deserializeHeadFromString(head);

		const key = this.getPrivateKeySync(de_head.id);

		return decryptRawAsymmetric(key, encrypted_data, head, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public async encrypt(data: Buffer, reply_id: string): Promise<Buffer>

	public async encrypt(data: Buffer, reply_id: string, sign: true): Promise<Buffer>

	public async encrypt(data: Buffer, reply_id: string, sign = false): Promise<Buffer>
	{
		const key = await this.getPublicKey(reply_id);

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.getSignKey();
		}

		return encryptAsymmetric(key.public_key, data, sign_key);
	}

	public encryptSync(data: Buffer, reply_public_key: string, sign = false)
	{
		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.getSignKeySync();
		}

		return encryptAsymmetric(reply_public_key, data, sign_key);
	}

	public decrypt(data: Buffer): Promise<Buffer>;

	public decrypt(data: Buffer, verify: boolean, user_id: string): Promise<Buffer>;

	public async decrypt(data: Buffer, verify = false, user_id?: string): Promise<Buffer>
	{
		const head: CryptoHead = splitHeadAndEncryptedData(data);
		const key = await this.getPrivateKey(head.id);

		if (!head?.sign || !verify || !user_id) {
			return decryptAsymmetric(key, data);
		}

		const verify_key = await Sentc.getUserVerifyKeyData(this.base_url, this.app_token, user_id, head.sign.id);

		return decryptAsymmetric(key, data, verify_key);
	}

	public decryptSync(data: Buffer, verify_key?: string)
	{
		const head: CryptoHead = splitHeadAndEncryptedData(data);
		const key = this.getPrivateKeySync(head.id);

		return decryptAsymmetric(key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public encryptString(data: string, reply_id:string): Promise<string>;

	public encryptString(data: string, reply_id:string, sign: true): Promise<string>;

	public async encryptString(data: string, reply_id: string, sign = false): Promise<string>
	{
		const key = await this.getPublicKey(reply_id);

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.getSignKey();
		}

		return encryptStringAsymmetric(key.public_key, data, sign_key);
	}

	public encryptStringSync(data: string, reply_public_key: string, sign = false)
	{
		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.getSignKeySync();
		}

		return encryptStringAsymmetric(reply_public_key, data, sign_key);
	}

	public decryptString(data: string): Promise<string>;

	public decryptString(data: string, verify: boolean, user_id: string): Promise<string>;

	public async decryptString(data: string, verify = false, user_id?: string): Promise<string>
	{
		const head: CryptoHead = splitHeadAndEncryptedString(data);
		const key = await this.getPrivateKey(head.id);

		if (!head?.sign || !verify || !user_id) {
			return decryptStringAsymmetric(key, data);
		}

		const verify_key = await Sentc.getUserVerifyKeyData(this.base_url, this.app_token, user_id, head.sign.id);

		return decryptStringAsymmetric(key, data, verify_key);
	}

	public decryptStringSync(data: string, verify_key?: string)
	{
		const head: CryptoHead = splitHeadAndEncryptedString(data);
		const key = this.getPrivateKeySync(head.id);

		return decryptStringAsymmetric(key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public async generateNonRegisteredKey(reply_id: string): Promise<[SymKey, string]>
	{
		const key_data = await this.getPublicKey(reply_id);

		const key_out = generateNonRegisterSymKeyByPublicKey(key_data.public_key);

		const encrypted_key = key_out.encryptedKey;
		const key = key_out.key;

		return [new SymKey(this.base_url, this.app_token, key, "non_register", key_data.public_key_id, await this.getSignKey()), encrypted_key];
	}

	public async getNonRegisteredKey(master_key_id: string, key: string)
	{
		const private_key = await this.getPrivateKey(master_key_id);

		return getNonRegisteredKeyByPrivateKey(private_key, key, master_key_id, await this.getSignKey());
	}
}