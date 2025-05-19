import Sentc from "../src";
import {assert} from "chai";

describe("Searchable tests", () => {
	const username0 = "test0";
	const username1 = "test1";

	const pw = "12345";

	/** @type User */
	let user0, user1;

	/** @type Group */
	let group, group_for_user_1;

	before(async () => {
		await Sentc.init({
			app_token: "5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
			base_url: "http://127.0.0.1:3002"
		});

		await Sentc.register(username0, pw);

		user0 = await Sentc.login(username0, pw, true);

		await Sentc.register(username1, pw);

		user1 = await Sentc.login(username1, pw, true);
	});

	it("should create a group", async function() {
		const group_id = await user0.createGroup();

		group = await user0.getGroup(group_id);

		assert.equal(group.data.group_id, group_id);
	});

	it("should invite the 2nd user in this group", async function() {
		await group.inviteAuto(user1.user_data.user_id);

		group_for_user_1 = await user1.getGroup(group.data.group_id);
	});

	const str = "123*+^êéèüöß@€&$ 👍 🚀 😎";
	/** @type string[] */
	let search_str_full, search_str;

	it("should create a full search str", function() {
		/** @type string[] */
		search_str_full = group.createSearchRaw(str, true);

		assert.equal(search_str_full.length, 1);
	});

	it("should create searchable item", function() {
		search_str = group.createSearchRaw(str);

		assert.equal(search_str.length, 39);
	});

	it("should search item", function() {
		//use the 2nd user
		const str_item = group_for_user_1.search(str);

		//should be in full
		assert.equal(search_str_full[0], str_item);

		//should be in the parts
		assert.equal(search_str.includes(str_item), true);
	});

	it("should search item in parts", function() {
		const str_item = group_for_user_1.search("123");
		assert.notEqual(search_str_full[0], str_item);

		assert.equal(search_str.includes(str_item), true);
	});

	after(async () => {
		//clean up

		await group.deleteGroup();

		await user0.deleteUser(pw);
		await user1.deleteUser(pw);
	});
});