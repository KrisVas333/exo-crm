-- EXO-CRM addition (2026-10-14): close public signup at the database level.
-- Every authenticated user can read every CRM row (upstream RLS = "to authenticated using (true)"),
-- so an open Supabase signup endpoint would expose all leads.
-- Rule: a new auth user is accepted only if the email is on private.crm_allowed_emails.
--   The first admin's email is inserted by hand at deploy time (SQL editor, not in this repo),
--   so a stranger who opens the fresh site first cannot claim the admin account.
--   Later emails are added by an admin invite (users edge function -> exo_allow_email).
-- Also switch off "Allow new users to sign up" in the Supabase dashboard (belt and braces).

create schema if not exists private;

create table if not exists private.crm_allowed_emails (
    email extensions.citext primary key,
    created_at timestamptz not null default now()
);
revoke all on private.crm_allowed_emails from anon, authenticated;

create or replace function public.exo_allow_email(p_email text)
returns void
language sql
security definer
set search_path = ''
as $$
    insert into private.crm_allowed_emails (email) values (lower(p_email))
    on conflict (email) do nothing;
$$;
revoke execute on function public.exo_allow_email(text) from public, anon, authenticated;
grant execute on function public.exo_allow_email(text) to service_role;

create or replace function private.exo_guard_signup()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not exists (
        select 1 from private.crm_allowed_emails a where a.email = lower(new.email)
    ) then
        raise exception 'Signup is closed. Ask an admin for an invite.';
    end if;
    return new;
end;
$$;

drop trigger if exists exo_guard_signup on auth.users;
create trigger exo_guard_signup
    before insert on auth.users
    for each row execute function private.exo_guard_signup();
