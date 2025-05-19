import {CryptoRawOutput} from "../Enities";
import {
	decryptRawSymmetric, decryptStringSymmetric, decryptSymmetric,
	doneFetchSymKey,
	doneFetchSymKeyByPrivateKey,
	encryptRawSymmetric, encryptStringSymmetric, encryptSymmetric
} from "@sentclose/sentc_node_js";

export function getNonRegisteredKey(master_key: string, key: string, master_key_id: string, sign_key: string)
{
	const key_out = doneFetchSymKey(master_key, key, true);

	return new SymKey("", "", key_out, "non_register", master_key_id, sign_key);
}

export function getNonRegisteredKeyByPrivateKey(private_key: string, key: string, master_key_id: string, sign_key: string)
{
	const key_out = doneFetchSymKeyByPrivateKey(private_key, key, true);

	return new SymKey("", "", key_out, "non_register", master_key_id, sign_key);
}

export class SymKey
{
	constructor(
		public base_url:string,
		public app_token: string,
		public key: string,
		public key_id: string,
		public master_key_id: string,	//this is important to save it to decrypt this key later
		private sign_key: string
	) {

	}

	public encryptRaw(data: Buffer): CryptoRawOutput;

	public encryptRaw(data: Buffer, sign: true): CryptoRawOutput;

	public encryptRaw(data: Buffer, sign = false): CryptoRawOutput
	{
		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.sign_key;
		}

		const out = encryptRawSymmetric(this.key, data, sign_key);

		return {
			head: out.head,
			data: out.data
		};
	}

	public decryptRaw(head: string, encrypted_data: Buffer): Buffer;

	public decryptRaw(head: string, encrypted_data: Buffer, verify_key: string): Buffer;

	public decryptRaw(head: string, encrypted_data: Buffer, verify_key?: string): Buffer
	{
		return decryptRawSymmetric(this.key, encrypted_data, head, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public encrypt(data: Buffer): Buffer

	public encrypt(data: Buffer, sign: true): Buffer

	public encrypt(data: Buffer, sign = false): Buffer
	{
		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.sign_key;
		}

		return encryptSymmetric(this.key, data, sign_key);
	}

	public decrypt(data: Buffer): Buffer;

	public decrypt(data: Buffer, verify_key: string): Buffer;

	public decrypt(data: Buffer, verify_key?: string): Buffer
	{
		return decryptSymmetric(this.key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public encryptString(data: string): string;

	public encryptString(data: string, sign: true): string;

	public encryptString(data: string, sign = false): string
	{
		let sign_key: string | undefined;

		if (sign) {
			sign_key = this.sign_key;
		}

		return encryptStringSymmetric(this.key, data, sign_key);
	}

	public decryptString(data: string): string;

	public decryptString(data: string, verify_key: string): string;

	public decryptString(data: string, verify_key?: string): string
	{
		return decryptStringSymmetric(this.key, data, verify_key);
	}
}