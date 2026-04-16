import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// protocol.js is loaded by the browser as a global script. Extract pure helpers
// (parseInteractionHeader, decodeJWTPayloadBrowser) by evaluating just the
// function declarations in a Node sandbox.
function extractFn(name: string): Function {
  const source = readFileSync(
    resolve(__dirname, '../public/protocol.js'),
    'utf-8'
  )
  // Match `function name(...) { ... }` up to its matching closing brace at column 0.
  const re = new RegExp(`function ${name}\\b[\\s\\S]*?\\n\\}\\n`, 'm')
  const match = source.match(re)
  if (!match) throw new Error(`Could not extract function ${name}`)
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(`${match[0]}\nreturn ${name};`)()
}

describe('parseInteractionHeader', () => {
  const parse = extractFn('parseInteractionHeader') as (h: string) => Record<string, string>

  it('parses requirement, url, and code', () => {
    const result = parse('requirement=interaction; url="https://ps.example/i"; code="ABCD1234"')
    expect(result).toEqual({
      requirement: 'interaction',
      url: 'https://ps.example/i',
      code: 'ABCD1234',
    })
  })

  it('strips surrounding double quotes from values', () => {
    const result = parse('foo="bar"')
    expect(result.foo).toBe('bar')
  })

  it('keeps unquoted values as-is', () => {
    const result = parse('requirement=interaction')
    expect(result.requirement).toBe('interaction')
  })

  it('skips parts without an equals sign', () => {
    const result = parse('requirement=interaction; garbage; url="https://x"')
    expect(result).toEqual({
      requirement: 'interaction',
      url: 'https://x',
    })
  })

  it('returns an empty object for empty input', () => {
    expect(parse('')).toEqual({})
  })
})

describe('decodeJWTPayloadBrowser', () => {
  const decode = extractFn('decodeJWTPayloadBrowser') as (jwt: string) => unknown

  it('decodes a standard JWT payload', () => {
    // header={"alg":"none"}; payload={"sub":"abc","n":1}; sig=""
    const jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhYmMiLCJuIjoxfQ.'
    expect(decode(jwt)).toEqual({ sub: 'abc', n: 1 })
  })

  it('returns null for malformed input', () => {
    expect(decode('not-a-jwt')).toBeNull()
  })

  it('handles base64url with - and _ characters', () => {
    // Payload: {"x":"a-b_c"} - which contains chars that base64url uses.
    const payload = Buffer.from('{"x":"a-b_c"}').toString('base64url')
    const jwt = `h.${payload}.s`
    expect(decode(jwt)).toEqual({ x: 'a-b_c' })
  })
})
