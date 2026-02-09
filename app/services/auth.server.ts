import { Authenticator } from "remix-auth";
import { FormStrategy } from "remix-auth-form";
import { createCookieSessionStorage, redirect } from "@remix-run/node";
import bcrypt from "bcryptjs";
import prisma from "../db.server";
import { Customer } from "@prisma/client";

// Export the session storage to use in routes
export const sessionStorage = createCookieSessionStorage({
    cookie: {
        name: "_looku_customer_session",
        sameSite: "lax",
        path: "/",
        httpOnly: true,
        secrets: [process.env.SESSION_SECRET || "default_secret_please_change"],
        secure: process.env.NODE_ENV === "production",
    },
});

// Create an instance of the authenticator
export const authenticator = new Authenticator<string>(sessionStorage);

authenticator.use(
    new FormStrategy(async ({ form }) => {
        const email = form.get("email") as string;
        const password = form.get("password") as string;

        const customer = await login(email, password);

        if (!customer) {
            throw new Error("Invalid email or password");
        }

        // And return the user id to store in the session
        return customer.id;
    }),
    "user-pass"
);

export async function login(email: string, password: string): Promise<Customer | null> {
    const customer = await prisma.customer.findUnique({
        where: { email },
    });

    if (!customer || !customer.passwordHash) return null;

    const isValid = await bcrypt.compare(password, customer.passwordHash);

    if (!isValid) return null;

    return customer;
}

export async function signup(
    email: string,
    password: string,
    firstName?: string,
    lastName?: string
): Promise<Customer> {
    const passwordHash = await bcrypt.hash(password, 10);

    // Create userToken if not provided. Using a random string for now.
    const userToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

    const customer = await prisma.customer.create({
        data: {
            email,
            passwordHash,
            firstName,
            lastName,
            userToken,
            shop: "default-shop", // TODO: Determine shop context
        },
    });

    return customer;
}

export async function requireCustomerId(
    request: Request,
    redirectTo: string = new URL(request.url).pathname
): Promise<string> {
    const session = await sessionStorage.getSession(
        request.headers.get("Cookie")
    );

    // Directly access the session data using the default key "user" or the one configured
    // remix-auth v3+ uses "user" by default if not specified
    const customerId = session.get("user");

    if (!customerId) {
        const searchParams = new URLSearchParams([
            ["redirectTo", redirectTo],
        ]);
        throw redirect(`/login?${searchParams}`);
    }

    return customerId;
}

export async function getCustomer(request: Request): Promise<Customer | null> {
    const session = await sessionStorage.getSession(request.headers.get("Cookie"));
    const customerId = session.get("user");

    if (!customerId) return null;

    return prisma.customer.findUnique({
        where: { id: customerId },
    });
}
