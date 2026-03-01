// app/api/auth/[...nextauth]/route.ts
import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import { prisma } from "@/constants/config/db";
import { RateLimiterMemory } from "rate-limiter-flexible";

const rateLimiter = new RateLimiterMemory({
  points: 5, // number of points
  duration: 60, // per 60 seconds
});

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    Credentials({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        if (!credentials) {
          console.error("No credentials provided.");
          return null;
        }
        const { email, password } = credentials as {
          email: string;
          password: string;
        };

        try {
          await rateLimiter.consume(email);
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
        } catch (rejRes) {
          // If rate limit is exceeded, throw an error
          throw new Error("Too many login attempts. Please try again later.");
        }

        try {
          const user = await prisma.user.findUnique({ where: { email } });
          if (!user) {
            console.error(`No user found for email: ${email}`);
            return null;
          }

          // Await bcrypt.compare to correctly check password
          const match = await bcrypt.compare(password, user.password);
          if (!match) {
            console.error(`Invalid password for email: ${email}`);
            return null;
          }

          // Remove the password field before returning user details
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          const { password: _removed, ...safeUser } = user;
          return safeUser;
        } catch (error) {
          console.error("Error in authorize callback:", error);
          return null;
        }
      },
    }),
  ],
  session: {
    strategy: "jwt",
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.role = user.role;
      }
      return token;
    },
    async session({ session, token }) {
      session.user.id = token.sub as string;
      session.user.role = token.role as string;
      return session;
    },
  },

  trustHost: true,
  pages: {
    signIn: "/login",
    error: "/login",
  },
});
