/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/27
 */
import {Mutex} from "./Mutex";
import {User} from "../User";
import {FileMetaFetched, FileMetaInformation, PartListItem} from "../Enities";
import {Sentc} from "../Sentc";
import {
	fileDownloadAndDecryptFilePart,
	fileDownloadAndDecryptFilePartStart,
	fileDownloadFileMeta,
	fileDownloadPartList
} from "@sentclose/sentc_node_js";
import {FileHandle, open, unlink, access, constants} from "node:fs/promises";
import * as path from "path";

export async function findAvailableFileName(file_path: string)
{
	const {name, dir, ext} = path.parse(file_path);

	let file_name = path.join(dir, name, ext);

	for (let i = 1; i < 20; i++) {
		try {
			// eslint-disable-next-line no-await-in-loop
			await access(file_name, constants.W_OK);
			file_name = path.join(dir, `${name}(${i})`, ext);
		} catch (e) {
			return file_name;
		}
	}
}

export class Downloader
{
	private static is_init = false;

	private static mutex: Mutex;

	public static cancel_download = false;

	public static init()
	{
		if (this.is_init) {
			return;
		}

		this.is_init = true;

		this.mutex = new Mutex();
	}

	constructor(
		private base_url: string,
		private app_token: string,
		private user: User,
		private group_id?: string,
		private readonly group_as_member?: string
	) {
		//the base url can be different when serving the files from a different storage

		Downloader.init();
	}

	/**
	 * Get the file info and the first page of the file part list
	 *
	 * @param file_id
	 */
	public async downloadFileMetaInformation(file_id: string): Promise<FileMetaInformation>
	{
		const jwt = await this.user.getJwt();

		const out = await fileDownloadFileMeta(this.base_url, this.app_token, jwt, file_id, this.group_id, this.group_as_member);

		const part_list: PartListItem[] = [];
		for (let i = 0; i < out.partList.length; i++) {
			const part = out.partList[i];
			part_list.push({
				part_id: part.partId,
				extern_storage: part.externStorage,
				sequence: part.sequence
			});
		}

		const file_meta: FileMetaFetched = {
			file_id: out.fileId,
			belongs_to: out.belongsTo,
			belongs_to_type: out.belongsToType,
			encrypted_file_name: out.encryptedFileName,
			encrypted_key: out.encryptedKey,
			encrypted_key_alg: out.encryptedKeyAlg,
			key_id: out.masterKeyId,
			master_key_id: out.masterKeyId,
			part_list
		};

		if (part_list.length >= 500) {
			//download parts via pagination
			let last_item = part_list[part_list.length - 1];
			let next_fetch = true;

			while (next_fetch) {
				// eslint-disable-next-line no-await-in-loop
				const fetched_parts = await this.downloadFilePartList(file_id, last_item);

				part_list.push(...fetched_parts);
				next_fetch = fetched_parts.length >= 500;
				last_item = fetched_parts[fetched_parts.length - 1];
			}
		}

		return {
			belongs_to: file_meta.belongs_to,
			belongs_to_type: file_meta.belongs_to_type,
			file_id: file_meta.file_id,
			master_key_id: file_meta.master_key_id,
			encrypted_key: file_meta.encrypted_key,
			encrypted_key_alg: file_meta.encrypted_key_alg,
			part_list,
			encrypted_file_name: file_meta.encrypted_file_name
		};
	}

	/**
	 * Download the rest of the part list via pagination
	 *
	 * @param file_id
	 * @param last_item
	 */
	public async downloadFilePartList(file_id: string, last_item: PartListItem | null = null): Promise<PartListItem[]>
	{
		const last_seq = last_item?.sequence + "" ?? "";

		const out = await fileDownloadPartList(this.base_url, this.app_token, file_id, last_seq);

		const part_list: PartListItem[] = [];
		for (let i = 0; i < out.length; i++) {
			const part = out[i];
			part_list.push({
				part_id: part.partId,
				extern_storage: part.externStorage,
				sequence: part.sequence
			});
		}

		return part_list;
	}

	public downloadFileParts(fileHandle: FileHandle, part_list: PartListItem[], content_key: string): Promise<void>;

	public downloadFileParts(fileHandle: FileHandle, part_list: PartListItem[], content_key: string, updateProgressCb: (progress: number) => void): Promise<void>;

	public downloadFileParts(fileHandle: FileHandle, part_list: PartListItem[], content_key: string, updateProgressCb: (progress: number) => void | undefined, verify_key: string): Promise<void>;

	public async downloadFileParts(
		fileHandle: FileHandle,
		part_list: PartListItem[],
		content_key: string,
		updateProgressCb?: (progress: number) => void,
		verify_key?: string
	) {
		const unlock = await Downloader.mutex.lock();

		Downloader.cancel_download = false;

		const url_prefix = Sentc.options?.file_part_url ?? undefined;

		let next_file_key: string = content_key;

		let offset = 0;

		for (let i = 0; i < part_list.length; i++) {
			const external = part_list[i].extern_storage === true;

			const part_url_base = (external) ? url_prefix : undefined;

			let part: Buffer | undefined;

			try {
				if (i === 0) {
					//first part
					// eslint-disable-next-line no-await-in-loop
					const res = await fileDownloadAndDecryptFilePartStart(
						this.base_url,
						part_url_base,
						this.app_token,
						part_list[i].part_id,
						content_key,
						verify_key
					);
					next_file_key = res.nextFileKey;
					part = res.file;
				} else {
					// eslint-disable-next-line no-await-in-loop
					const res = await fileDownloadAndDecryptFilePart(
						this.base_url,
						part_url_base,
						this.app_token,
						part_list[i].part_id,
						next_file_key,
						verify_key
					);
					next_file_key = res.nextFileKey;
					part = res.file;
				}
			} catch (e) {
				// eslint-disable-next-line no-await-in-loop
				unlock();
				throw e;
			}

			if (!part) {
				// eslint-disable-next-line no-await-in-loop
				unlock();
				throw Error("Part not found");
			}

			// eslint-disable-next-line no-await-in-loop
			await fileHandle.write(part, 0, part.length, offset);

			offset += part.length;

			if (updateProgressCb) {
				updateProgressCb((i + 1) / part_list.length);
			}

			if (Downloader.cancel_download) {
				Downloader.cancel_download = false;

				// eslint-disable-next-line no-await-in-loop
				unlock();
				return;
			}
		}

		unlock();
	}

	public downloadFilePartsWithPath(path: string, part_list: PartListItem[], content_key: string): Promise<void>;

	public downloadFilePartsWithPath(path: string, part_list: PartListItem[], content_key: string, updateProgressCb: (progress: number) => void): Promise<void>;

	public downloadFilePartsWithPath(path: string, part_list: PartListItem[], content_key: string, updateProgressCb: (progress: number) => void | undefined, verify_key: string): Promise<void>;

	public async downloadFilePartsWithPath(
		path: string,
		part_list: PartListItem[],
		content_key: string,
		updateProgressCb?: (progress: number) => void,
		verify_key?: string
	) {
		const file_handle = await open(path, "a");

		try {
			await this.downloadFileParts(file_handle, part_list, content_key, updateProgressCb, verify_key);
		} catch (e) {
			await unlink(path);

			throw e;
		} finally {
			await file_handle.close();
		}
	}
}