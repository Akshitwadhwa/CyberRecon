const SOURCES = new Set(['network', 'endpoint', 'identity', 'alert_image'])
const EVENT_ID = /^(id|ep|net|al)-\d+$/

export function parseIncidentJson(text) {
  let value
  try {
    value = JSON.parse(text)
  } catch {
    throw new Error('Enter a valid JSON object.')
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Incident JSON must be an object.')
  }
  const required = ['id', 'title', 't_start', 't_end', 'ticket_text', 'events']
  const missing = required.find(key => value[key] === undefined)
  if (missing) throw new Error(`Incident JSON is missing '${missing}'.`)
  if (!Array.isArray(value.events)) throw new Error('Incident events must be an array.')
  const ids = new Set()
  for (const event of value.events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new Error('Each event must be an object.')
    for (const key of ['id', 'timestamp', 'source', 'event_type', 'payload']) {
      if (event[key] === undefined) throw new Error(`Each event must include '${key}'.`)
    }
    if (!EVENT_ID.test(event.id)) throw new Error(`Invalid event ID '${event.id}'.`)
    if (ids.has(event.id)) throw new Error(`Duplicate event ID '${event.id}'.`)
    ids.add(event.id)
    if (!SOURCES.has(event.source)) throw new Error(`Invalid event source '${event.source}'.`)
    if (!event.payload || typeof event.payload !== 'object' || Array.isArray(event.payload)) throw new Error(`Payload for '${event.id}' must be an object.`)
  }
  return value
}
