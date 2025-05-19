import {StorageInterface, InitReturn} from "@sentclose/sentc-common/lib/FileStorage/StorageInterface";
import * as fs from "fs/promises";
import * as path from "path";

export class FileSystemStorage implements StorageInterface
{
	private readonly storageDir: string;


	public isInit = false;

	constructor(private dbName: string = "sentc_encrypt_files") {
		this.storageDir = path.join(process.cwd(), this.dbName);

	}

	public async init(): Promise<InitReturn>
	{
		try {
			// Create a directory structure if it doesn't exist
			await fs.mkdir(this.storageDir, {recursive: true});

			this.isInit = true;
			return {status: true};
		} catch (e: any) {
			return {
				status: false,
				err: `FileSystem storage initialization failed: ${e.message}`
			};
		}
	}

	// eslint-disable-next-line require-await
	public async getDownloadUrl(): Promise<string>
	{
		throw new Error("Not implemented");
	}

	// eslint-disable-next-line require-await
	public async cleanStorage(): Promise<void>
	{
		throw new Error("Not implemented");
	}

	// eslint-disable-next-line require-await
	public async storePart(chunk: ArrayBuffer): Promise<void>
	{
		throw new Error("Not implemented");
	}

	public async delete(key: string): Promise<void>
	{
		try {
			const filePath = path.join(this.storageDir, key);

			// Check if a file exists before trying to delete
			try {
				await fs.access(filePath);
				await fs.unlink(filePath);
			} catch (accessError) {
				// File doesn't exist, ignore
			}
		} catch (e) {
			console.error(`Failed to delete item with key ${key}:`, e);
			throw e;
		}
	}

	public async getItem(key: string): Promise<any>
	{
		try {
			const filePath = path.join(this.storageDir, key);

			try {
				await fs.access(filePath);
				const content = await fs.readFile(filePath, "utf8");
				return deserializeWithMaps(content);
			} catch (accessError) {
				// File doesn't exist
				return null;
			}
		} catch (e) {
			console.error(`Failed to get item with key ${key}:`, e);
			throw e;
		}
	}

	public async set(key: string, item: any): Promise<void>
	{
		try {
			const filePath = path.join(this.storageDir, key);
			await fs.writeFile(filePath, serializeWithMaps(item));
		} catch (e) {
			console.error(`Failed to set item with key ${key}:`, e);
			throw e;
		}
	}
}

function serializeWithMaps(obj) {
	const replacer = (key, value) => {
		if (value instanceof Map) {
			return {
				// eslint-disable-next-line @typescript-eslint/naming-convention
				__type: "Map",
				entries: Array.from(value.entries())
			};
		}
		return value;
	};

	return JSON.stringify(obj, replacer);
}


function deserializeWithMaps(jsonString: string) {
	const reviver = (key, value) => {
		if (value && value.__type === "Map" && Array.isArray(value.entries)) {
			return new Map(value.entries);
		}
		return value;
	};

	return JSON.parse(jsonString, reviver);
}
