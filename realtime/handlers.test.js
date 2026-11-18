const assert = require("node:assert/strict");
const { test } = require("node:test");

const frappe_handlers = require("./handlers");

function make_socket(user) {
	const events = new Map();
	const rooms = new Set();
	frappe_handlers({
		user,
		rooms,
		on: (event, handler) => events.set(event, handler),
		join: (room) => rooms.add(room),
		leave: (room) => rooms.delete(room),
	});
	return { events, rooms };
}

for (const event of ["task_subscribe", "progress_subscribe"]) {
	test(`${event} only joins the caller's task room`, () => {
		const owner = make_socket("owner@example.com");
		const other = make_socket("other@example.com");
		const guest = make_socket("Guest");
		const room = "task_progress:owner@example.com:export:1";

		for (const socket of [owner, other, guest]) {
			socket.events.get(event)("export:1");
		}

		assert.ok(owner.rooms.has(room));
		assert.ok(other.rooms.has("task_progress:other@example.com:export:1"));
		assert.ok(!other.rooms.has(room));
		assert.ok(![...guest.rooms].some((room) => room.startsWith("task_progress:")));

		owner.events.get("task_unsubscribe")("export:1");
		assert.ok(!owner.rooms.has(room));
	});
}
