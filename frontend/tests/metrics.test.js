import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeEvaluationMetrics } from '../src/api.js'

test('missing evaluation metrics remain unavailable instead of becoming zero', () => {
  assert.deepEqual(normalizeEvaluationMetrics({ metrics: {} }), {
    totalMs: null,
    a2aMs: null,
    tokens: null,
    spans: null,
    grounded: null,
    mcpCalls: null,
    ragCalls: null,
  })
})

test('evaluation metrics preserve measured values', () => {
  assert.deepEqual(normalizeEvaluationMetrics({ metrics: {
    timing: { total_duration_ms: 12, a2a_duration_ms: 4, mcp_tool_calls: 3, rag_calls: 1 },
    llm: { token_usage: { total_tokens: 88 } },
    trace: { span_count: 5 },
    grounding: { passed: true },
  } }), {
    totalMs: 12,
    a2aMs: 4,
    tokens: 88,
    spans: 5,
    grounded: true,
    mcpCalls: 3,
    ragCalls: 1,
  })
})
