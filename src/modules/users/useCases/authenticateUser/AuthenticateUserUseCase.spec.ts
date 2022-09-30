import { hash } from "bcryptjs";

import { InMemoryUsersRepository } from "../../repositories/in-memory/InMemoryUsersRepository";
import { IUsersRepository } from "../../repositories/IUsersRepository";
import { AuthenticateUserUseCase } from "./AuthenticateUserUseCase";
import { IncorrectEmailOrPasswordError } from "./IncorrectEmailOrPasswordError";

let usersRepository: IUsersRepository;
let authenticateUserUseCase: AuthenticateUserUseCase;

describe("AuthenticateUserUseCase", () => {
  beforeEach(() => {
    usersRepository = new InMemoryUsersRepository();
    authenticateUserUseCase = new AuthenticateUserUseCase(usersRepository);
  });

  it("should be able to authenticate", async () => {
    await usersRepository.create({
      email: "test@email.com",
      name: "test",
      password: await hash("senha", 8),
    });

    const response = await authenticateUserUseCase.execute({
      email: "test@email.com",
      password: "senha",
    });

    expect(response).toHaveProperty("token");
    expect(response).toHaveProperty("user");
  });

  it("should not be able to authenticate with a non-existent user", async () => {
    expect(async () => {
      await authenticateUserUseCase.execute({
        email: "no@exists.com",
        password: "non-exists",
      });
    }).rejects.toBeInstanceOf(IncorrectEmailOrPasswordError);
  });

  it("should not be able to authenticate with a wrong password", async () => {
    expect(async () => {
      await usersRepository.create({
        email: "test@email.com",
        name: "test",
        password: await hash("senha", 8),
      });

      await authenticateUserUseCase.execute({
        email: "test@email.com",
        password: "wrongpass",
      });
    }).rejects.toBeInstanceOf(IncorrectEmailOrPasswordError);
  });

  it("should not be able to authenticate with a wrong email", async () => {
    expect(async () => {
      await usersRepository.create({
        email: "test@email.com",
        name: "test",
        password: await hash("senha", 8),
      });

      const response = await authenticateUserUseCase.execute({
        email: "no@exists.com",
        password: "senha",
      });
    }).rejects.toBeInstanceOf(IncorrectEmailOrPasswordError);
  });
});
