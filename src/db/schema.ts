import {
  pgTable,
  serial,
  text,
  integer,
  timestamp,
} from "drizzle-orm/pg-core";

// Saved SSTP endpoints managed from the control panel. These describe how to
// invoke the standalone sstp-proxy client; no live VPN state is stored here.
export const savedServers = pgTable("saved_servers", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  host: text("host").notNull(),
  port: integer("port").notNull().default(443),
  username: text("username").notNull().default("vpn"),
  password: text("password").notNull().default("vpn"),
  country: text("country").notNull().default(""),
  auth: text("auth").notNull().default("auto"),
  socksAddr: text("socks_addr").notNull().default("127.0.0.1:1080"),
  httpAddr: text("http_addr").notNull().default("127.0.0.1:8080"),
  notes: text("notes").notNull().default(""),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type SavedServer = typeof savedServers.$inferSelect;
export type NewSavedServer = typeof savedServers.$inferInsert;
