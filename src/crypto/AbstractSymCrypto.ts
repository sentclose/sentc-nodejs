import {CryptoHead, CryptoRawOutput} from "../Enities";
import {AbstractCrypto} from "./AbstractCrypto";
import {getNonRegisteredKey, SymKey} from "./SymKey";
import {Sentc} from "../Sentc";
import {
	decryptRawSymmetric, decryptStringSymmetric, decryptSymmetric,
	deserializeHeadFromString,
	encryptRawSymmetric, encryptStringSymmetric,
	encryptSymmetric, generateNonRegisterSymKey, splitHeadAndEncryptedData, splitHeadAndEncryptedString
} from "@sentclose/sentc_node_js";

/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/19
 */

export abstract class AbstractSymCrypto extends AbstractCrypto
{
	/**
	 * The latest used key (e.g., the latest group key)
	 *
	 * return the key and the key id
	 */
	abstract getSymKeyToEncrypt(): Promise<[string, string]>;

	abstract getSymKeyToEncryptSync(): [string, string];

	abstract getSymKeyById(key_id: string): Promise<string>;

	abstract getSymKeyByIdSync(key_id: string): string;

	abstract getSignKey(): Promise<string>;

	abstract getSignKeySync(): string;

	abstract getJwt(): Promise<string>;

	public encryptRaw(data: Buffer): Promise<CryptoRawOutput>;

	public encryptRaw(data: Buffer, sign: true): Promise<CryptoRawOutput>;

	public async encryptRaw(data: Buffer, sign = false): Promise<CryptoRawOutput>
	{
		const key = await this.getSymKeyToEncrypt();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.getSignKey();
		}

		const out = encryptRawSymmetric(key[0], data, sign_key);

		return {
			head: out.head,
			data: out.data
		};
	}

	public encryptRawSync(data: Buffer, sign = false): CryptoRawOutput
	{
		const key = this.getSymKeyToEncryptSync();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.getSignKeySync();
		}

		const out = encryptRawSymmetric(key[0], data, sign_key);

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

		const key = await this.getSymKeyById(de_head.id);

		return decryptRawSymmetric(key, encrypted_data, head, verify_key);
	}

	public decryptRawSync(head: string, encrypted_data: Buffer, verify_key?: string): Buffer
	{
		const de_head: CryptoHead = deserializeHeadFromString(head);

		const key = this.getSymKeyByIdSync(de_head.id);

		return decryptRawSymmetric(key, encrypted_data, head, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public async encrypt(data: Buffer): Promise<Buffer>

	public async encrypt(data: Buffer, sign: true): Promise<Buffer>

	public async encrypt(data: Buffer, sign = false): Promise<Buffer>
	{
		const key = await this.getSymKeyToEncrypt();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.getSignKey();
		}

		return encryptSymmetric(key[0], data, sign_key);
	}

	public encryptSync(data: Buffer, sign = false): Buffer
	{
		const key = this.getSymKeyToEncryptSync();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.getSignKeySync();
		}

		return encryptSymmetric(key[0], data, sign_key);
	}

	public decrypt(data: Buffer): Promise<Buffer>;

	public decrypt(data: Buffer, verify: true, user_id: string): Promise<Buffer>;

	public async decrypt(data: Buffer, verify = false, user_id?: string): Promise<Buffer>
	{
		const head: CryptoHead = splitHeadAndEncryptedData(data);

		const key = await this.getSymKeyById(head.id);

		if (!head?.sign || !verify || !user_id) {
			return decryptSymmetric(key, data);
		}

		const verify_key = await Sentc.getUserVerifyKeyData(this.base_url, this.app_token, user_id, head.sign.id);

		return decryptSymmetric(key, data, verify_key);
	}

	public decryptSync(data: Buffer, verify_key?: string): Buffer
	{
		const head: CryptoHead = splitHeadAndEncryptedData(data);

		const key = this.getSymKeyByIdSync(head.id);

		return decryptSymmetric(key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public encryptString(data: string): Promise<string>;

	public encryptString(data: string, sign: true): Promise<string>;

	public async encryptString(data: string, sign = false): Promise<string>
	{
		const key = await this.getSymKeyToEncrypt();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.getSignKey();
		}

		return encryptStringSymmetric(key[0], data, sign_key);
	}

	public encryptStringSync(data: string, sign = false): string
	{
		const key = this.getSymKeyToEncryptSync();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.getSignKeySync();
		}

		return encryptStringSymmetric(key[0], data, sign_key);
	}

	public decryptString(data: string): Promise<string>;

	public decryptString(data: string, verify_key: true, user_id: string): Promise<string>;

	public async decryptString(data: string, verify = false, user_id?: string): Promise<string>
	{
		const head: CryptoHead = splitHeadAndEncryptedString(data);

		const key = await this.getSymKeyById(head.id);

		if (!head?.sign || !verify || !user_id) {
			return decryptStringSymmetric(key, data);
		}

		const verify_key = await Sentc.getUserVerifyKeyData(this.base_url, this.app_token, user_id, head.sign.id);

		return decryptStringSymmetric(key, data, verify_key);
	}

	public decryptStringSync(data: string, verify_key?: string): string
	{
		const head: CryptoHead = splitHeadAndEncryptedString(data);

		const key = this.getSymKeyByIdSync(head.id);

		return decryptStringSymmetric(key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public async generateNonRegisteredKey(): Promise<[SymKey, string]>
	{
		const key_data = await this.getSymKeyToEncrypt();

		const key_out = generateNonRegisterSymKey(key_data[0]);

		const encrypted_key = key_out.encryptedKey;
		const key = key_out.key;

		return [new SymKey(this.base_url, this.app_token, key, "non_register", key_data[1], await this.getSignKey()), encrypted_key];
	}

	public async getNonRegisteredKey(master_key_id: string, key: string)
	{
		const master_key = await this.getSymKeyById(master_key_id);

		return getNonRegisteredKey(master_key, key, master_key_id, await this.getSignKey());
	}

	//__________________________________________________________________________________________________________________
}