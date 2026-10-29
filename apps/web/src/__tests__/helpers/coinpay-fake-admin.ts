/** Just enough of a service-role supabase client for coinpay_identities + auth.admin. */
type Row = { sub: string; user_id: string; email: string | null; name: string | null };

export function fakeAdmin(seed: { identities?: Row[]; users?: { id: string; email: string }[] } = {}) {
  const identities: Row[] = [...(seed.identities ?? [])];
  const users = [...(seed.users ?? [])];
  const profiles: Record<string, unknown>[] = [];
  const admin = {
    identities,
    users,
    profiles,
    from(table: string) {
      if (table === "user_profiles") return { insert: async (row: Record<string, unknown>) => (profiles.push(row), { error: null }) };
      return {
        select: () => ({
          eq: (col: keyof Row, value: string) => ({
            maybeSingle: async () => ({ data: identities.find((r) => r[col] === value) ?? null }),
          }),
        }),
        insert: async (row: Row) => {
          if (identities.some((r) => r.sub === row.sub || r.user_id === row.user_id)) return { error: { message: "duplicate" } };
          identities.push(row);
          return { error: null };
        },
        update: (patch: Partial<Row>) => ({
          eq: async (col: keyof Row, value: string) => {
            identities.filter((r) => r[col] === value).forEach((r) => Object.assign(r, patch));
            return { error: null };
          },
        }),
      };
    },
    auth: {
      admin: {
        createUser: async ({ email }: { email: string }) => {
          const user = { id: `u${users.length + 1}`, email };
          users.push(user);
          return { data: { user }, error: null };
        },
        getUserById: async (id: string) => ({ data: { user: users.find((u) => u.id === id) ?? null } }),
        deleteUser: async (id: string) => {
          users.splice(users.findIndex((u) => u.id === id), 1);
          return { error: null };
        },
      },
    },
  };
  return admin;
}

