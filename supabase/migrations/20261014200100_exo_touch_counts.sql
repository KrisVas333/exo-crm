-- EXO-CRM addition (2026-10-14): "how many times did I communicate" per contact.
-- Convention: each communication is a contact note whose text starts with
--   📤 = outbound touch (email/call/chat/ExoSend)   📥 = inbound (reply, form, call back)
-- Fields inside the note text: Kanalas · Tema · Atidarė · Paspaudė · Atsakė (empty/⚠️ = unknown, never false).
create or replace view public.exo_contact_touches
with (security_invoker = true) as
select
    c.id as contact_id,
    concat_ws(' ', c.first_name, c.last_name) as contact_name,
    co.name as company_name,
    count(n.id) filter (where n.text like '📤%') as outbound_touches,
    count(n.id) filter (where n.text like '📥%') as inbound_touches,
    max(n.date) filter (where n.text like '📤%') as last_outbound,
    max(n.date) filter (where n.text like '📥%') as last_inbound
from public.contacts c
left join public.companies co on co.id = c.company_id
left join public.contact_notes n on n.contact_id = c.id
group by c.id, c.first_name, c.last_name, co.name;

grant select on public.exo_contact_touches to authenticated;
revoke all on public.exo_contact_touches from anon;
