import {User} from "../User";
import {Sentc} from "../Sentc";
import {
	fileDoneRegisterFile,
	filePrepareRegisterFile, fileRegisterFile,
	fileUploadPart,
	fileUploadPartStart
} from "@sentclose/sentc_node_js";
import {FileHandle, open} from "node:fs/promises";
import {basename} from "node:path";

/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/27
 */

export class Uploader
{
	private readonly belongs_to_id?: string;

	private readonly belongs_to?: string;

	public static cancel_upload = false;

	constructor(
		private base_url: string,
		private app_token: string,
		private user: User,
		private group_id?: string,
		private other_user_id?: string,
		private upload_callback?: (progress?: number) => void,
		private readonly group_as_member?: string,
		private chunk_size = 1024 * 1024 * 4
	) {
		if (group_id && group_id !== "") {
			this.belongs_to_id = group_id;
			this.belongs_to = "\"Group\"";	//the double "" are important for rust serde JSON
		} else if (other_user_id && other_user_id !== "") {
			this.belongs_to_id = other_user_id;
			this.belongs_to = "\"User\"";
		} else {
			this.belongs_to = "\"None\"";
		}
	}

	public prepareFileRegister(file: File, content_key: string, encrypted_content_key: string, master_key_id: string)
	{
		const out = filePrepareRegisterFile(
			master_key_id,
			content_key,
			encrypted_content_key,
			this.belongs_to_id,
			this.belongs_to,
			file.name
		);
		
		const encrypted_file_name = out.encryptedFileName;
		const server_input = out.serverInput;

		return [server_input, encrypted_file_name];
	}

	public doneFileRegister(server_output: string)
	{
		const out = fileDoneRegisterFile(server_output);

		const file_id = out.fileId;
		const session_id = out.sessionId;

		return [file_id, session_id];
	}

	public async checkFileUpload(fileHandle: FileHandle, fileSize: number, content_key: string, session_id: string, sign = false)
	{
		const jwt = await this.user.getJwt();

		let sign_key: string | undefined;

		if (sign) {
			sign_key = await this.user.getSignKey();
		}

		const totalChunks = Math.ceil(fileSize / this.chunk_size);
		let offset = 0;
		let currentChunk = 0;

		//reset it just in case it was true
		Uploader.cancel_upload = false;

		const url_prefix = Sentc.options?.file_part_url ?? undefined;

		//each file is encrypted by a new key, and this key is encrypted by the pre-key
		let next_file_key: string = content_key;

		while (offset < fileSize) {
			const remaining = fileSize - offset;
			const readSize = Math.min(this.chunk_size, remaining);
			const buffer = Buffer.alloc(readSize);

			// eslint-disable-next-line no-await-in-loop
			const {bytesRead} = await fileHandle.read(buffer, 0, readSize, offset);
			if (bytesRead === 0) {break;}

			const isEnd = offset + bytesRead >= fileSize;

			++currentChunk;

			if (currentChunk === 1) {
				//first chunk
				// eslint-disable-next-line no-await-in-loop
				next_file_key = await fileUploadPartStart(
					this.base_url,
					url_prefix,
					this.app_token,
					jwt,
					session_id,
					isEnd,
					currentChunk,
					content_key,
					sign_key,
					buffer
				);
			} else {
				// eslint-disable-next-line no-await-in-loop
				next_file_key = await fileUploadPart(
					this.base_url,
					url_prefix,
					this.app_token,
					jwt,
					session_id,
					isEnd,
					currentChunk,
					next_file_key,
					sign_key,
					buffer
				);
			}

			if (this.upload_callback) {
				this.upload_callback(currentChunk / totalChunks);
			}

			offset += bytesRead;

			if (Uploader.cancel_upload) {
				Uploader.cancel_upload = false;
				break;
			}
		}
	}

	public async uploadFileWithPath(path: string, content_key: string, encrypted_content_key: string, master_key_id: string, sign = false)
	{
		const file_handle = await open(path, "r");

		let result;

		try {
			const file_name = basename(path);

			result = await this.uploadFile(file_handle, file_name, content_key, encrypted_content_key, master_key_id, sign);
		} finally {
			await file_handle.close();
		}

		return result;
	}

	public async uploadFile(file: FileHandle, file_name: string, content_key: string, encrypted_content_key: string, master_key_id: string, sign = false)
	{
		const jwt = await this.user.getJwt();
		const stats = await file.stat();

		//create a new file on the server and save the content key id
		const out = await fileRegisterFile(
			this.base_url,
			this.app_token,
			jwt,
			master_key_id,
			content_key,
			encrypted_content_key,
			this.belongs_to_id,
			this.belongs_to,
			file_name,
			this.group_id,
			this.group_as_member
		);

		const session_id = out.sessionId;
		const file_id = out.fileId;
		const encrypted_file_name = out.encryptedFileName;

		await this.checkFileUpload(file, stats.size, content_key, session_id, sign);

		return [file_id, encrypted_file_name];
	}
}