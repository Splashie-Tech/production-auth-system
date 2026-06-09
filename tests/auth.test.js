const request = require("supertest");
const app = require("../server");

describe("Auth System", () => {

  it("should register a user", async () => {

    const res = await request(app)
      .post("/api/register")
      .send({
        name: "Test User",
        email: `test${Date.now()}@example.com`,
        password: "123456@Auuu"
      });

    expect(res.statusCode).toBe(201);
  });

});