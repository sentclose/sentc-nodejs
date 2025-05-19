import Sentc, {Group} from "../src";
import {assert} from "chai";

describe("Sortable test 2", () => {
	before(async () => {
		await Sentc.init({
			app_token: "5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
			base_url: "http://127.0.0.1:3002"
		});
	});

	it("should generate the same numbers with same key", function() {
		//dummy group
		//@ts-ignore
		const group = new Group({
			sortable_keys: [`{"Ope16":{"key":"5kGPKgLQKmuZeOWQyJ7vOg==","key_id":"1876b629-5795-471f-9704-0cac52eaf9a1"}}`]
		}, "", "", null);

		const a = group.encryptSortableRawNumber(262);
		const b = group.encryptSortableRawNumber(263);
		const c = group.encryptSortableRawNumber(65321);

		// eslint-disable-next-line no-console
		console.log(`a: ${a}, b: ${b}, c: ${c}`);

		assert.equal((a < b), true);
		assert.equal((b < c), true);
	});
});