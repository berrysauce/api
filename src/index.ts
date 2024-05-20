import { Hono, Context } from "hono"
import { authHandler, initAuthConfig, verifyAuth, type AuthConfig } from "@hono/auth-js"
import GitHub from "@auth/core/providers/github"

type Bindings = {
  DOMAINS_KV: KVNamespace,
  OAUTH_SECRET: string,
  GH_OAUTH_ID: string,
  GH_OAUTH_SECRET: string
}

const app = new Hono<{ Bindings: Bindings }>()

// Authentication middleware

app.use("*", initAuthConfig(getAuthConfig))

app.use("/api/auth/*", authHandler())

app.use("/api/*", verifyAuth())

app.get("/api/protected", (c) => {
  const auth = c.get("authUser")
  return c.json(auth)
})

function getAuthConfig(c: Context): AuthConfig {
  return {
    secret: c.env.OAUTH_SECRET,
    providers: [
      GitHub({
        clientId: c.env.GH_OAUTH_ID,
        clientSecret: c.env.GH_OAUTH_SECRET
      }),
    ]
  }
}

// Routes

app.get("/", async (c) => {
  return c.text("Stowage API")
})

app.get("/api/kv", async (c, next) => {
  return c.newResponse(await c.env.DOMAINS_KV.get("stowage.stowage.dev"))
})

export default app
