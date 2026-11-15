import test from 'node:test'
import assert from 'node:assert/strict'
import { parseIncidentJson } from '../src/incidentValidation.js'

const valid = {
  id: 'case-c', title: 'Impossible travel', t_start: '2026-09-09T08:00:00',
  t_end: '2026-09-09T08:20:00', ticket_text: 'Identity alert',
  events: [{ id: 'id-20', timestamp: '2026-09-09T08:02:10', source: 'identity', event_type: 'login_success', payload: { user: 'anish' } }],
}

test('accepts a complete incident record', () => {
  assert.deepEqual(parseIncidentJson(JSON.stringify(valid)), valid)
})

test('rejects malformed and incomplete JSON', () => {
  assert.throws(() => parseIncidentJson('{'), /valid JSON/)
  assert.throws(() => parseIncidentJson(JSON.stringify({ ...valid, events: undefined })), /missing 'events'/)
})

test('rejects invalid event source and duplicate IDs', () => {
  assert.throws(() => parseIncidentJson(JSON.stringify({ ...valid, events: [{ ...valid.events[0], source: 'unknown' }] })), /Invalid event source/)
  assert.throws(() => parseIncidentJson(JSON.stringify({ ...valid, events: [valid.events[0], valid.events[0]] })), /Duplicate event ID/)
})
