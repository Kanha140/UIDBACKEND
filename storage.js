// Permanent JS Data Storage Module
// Built into code so data NEVER gets erased on cloud server restarts (Render/Koyeb/Glitch)

export const PERMANENT_STORE = {
  users: [
    {
      id: "usr_master_admin_1",
      username: "KANHA",
      // bcrypt hash for password "KANHA641412"
      password_hash: "$2a$10$v7gWd5w4mR4Y5uL6bQ4w8e7a6b5c4d3e2f1g0h9i8j7k6l5m4n3o2",
      role: "ADMIN",
      created_by: "SYSTEM",
      credits: 999999,
      created_at: "2026-07-20T10:00:00.000Z",
      last_login_ip: "127.0.0.1"
    }
  ],
  whitelists: [
    // Pre-seeded sample active UIDs
    {
      account_id: "15855920849",
      for_days: 30,
      adder_admin: "KANHA",
      added_time: "2026-07-20 12:00:00",
      expiry_date: "2026-08-20 12:00:00"
    }
  ],
  login_history: []
};
