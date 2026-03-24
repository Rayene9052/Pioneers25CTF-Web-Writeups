// Runs inside the Mongo container at first startup
const dbName = "ctf";
const db = db.getSiblingDB(dbName);

// UPDATED seed values
const adminPassword = "Y0U_H4v3_n0_3n3m1es_br0th3r!";
const flag = "Pioneers25{F4r_t0_th3_w3st_Acr0ss_th3_s3a_th3r3_1s_4_laNd_c4ll3d_Vinland}";

db.users.drop();
db.reports.drop();

db.users.insertMany([
  { username: "admin", password: adminPassword, role: "admin" },
  { username: "guest", password: "guest", role: "user" }
]);

db.reports.insertMany([
  { title: "Quarterly Shipping Notes", content: "Routes stable, supplies nominal.", visibility: "internal" },
  { title: "Crew Manifest", content: "All hands accounted for.", visibility: "internal" },
  { title: "Internal Flag Report", content: flag, visibility: "internal" }
]);

print("[mongo-init] Seeded users + reports");