// Supabase Edge Function: functions/admin-user/index.ts
// Deploy with: supabase functions deploy admin-user
//
// This function keeps the service-role key on the server.
// NEVER put SUPABASE_SERVICE_ROLE_KEY in index.html.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS"
};

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" }
  });
}

const adminClient = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return response({error:"Method not allowed"}, 405);

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) return response({error:"Missing authorization"}, 401);

    const token = authHeader.replace("Bearer ", "");
    const {data:{user}, error:userError} = await adminClient.auth.getUser(token);
    if (userError || !user) return response({error:"Invalid session"}, 401);

    const {data: me, error:meError} = await adminClient
      .from("profiles")
      .select("role,active")
      .eq("id", user.id)
      .maybeSingle();

    if (meError || !me || me.role !== "superadmin" || me.active !== true) {
      return response({error:"Superadmin permission required"}, 403);
    }

    const body = await req.json();
    const action = body.action;
    const username = String(body.username || "").trim();

    if (!username) return response({error:"Username is required"}, 400);

    const email = `${username.toLowerCase()}@users.premeal.local`;

    if (action === "create") {
      const password = String(body.password || "");
      const role = body.role === "superadmin" ? "superadmin" : "user";

      if (password.length < 6)
        return response({error:"Password must be at least 6 characters"}, 400);

      const {data: created, error:createError} =
        await adminClient.auth.admin.createUser({
          email,
          password,
          email_confirm: true,
          user_metadata: { username }
        });

      if (createError) return response({error:createError.message}, 400);

      const {error:profileError} = await adminClient.from("profiles").insert({
        id: created.user.id,
        username,
        email,
        role,
        active: true
      });

      if (profileError) {
        await adminClient.auth.admin.deleteUser(created.user.id);
        return response({error:profileError.message}, 400);
      }

      return response({ok:true});
    }

    const {data: profile, error:profileError} = await adminClient
      .from("profiles")
      .select("id")
      .eq("username", username)
      .maybeSingle();

    if (profileError || !profile) return response({error:"Account not found"}, 404);

    if (action === "reset_password") {
      const password = String(body.password || "");
      if (password.length < 6)
        return response({error:"Password must be at least 6 characters"}, 400);

      const {error} = await adminClient.auth.admin.updateUserById(
        profile.id,
        {password}
      );
      if (error) return response({error:error.message}, 400);
      return response({ok:true});
    }

    if (action === "delete") {
      if (profile.id === user.id)
        return response({error:"You cannot delete the currently logged-in admin"}, 400);

      const {error} = await adminClient.auth.admin.deleteUser(profile.id);
      if (error) return response({error:error.message}, 400);

      return response({ok:true});
    }

    return response({error:"Unknown action"}, 400);
  } catch (err) {
    return response({error: String(err)}, 500);
  }
});
