import { describe, expect, it } from 'vitest'
import { bytes, cn, hexDump, shortHash } from '@/utils/format'

describe('format utils', () => {
  it('formats byte sizes', () => {
    expect(bytes(512)).toBe('512 B')
    expect(bytes(2048)).toBe('2.0 KB')
    expect(bytes(5 * 1024 ** 2)).toBe('5.00 MB')
  })
  it('shortens long hashes only', () => {
    expect(shortHash('abc', 10)).toBe('abc')
    expect(shortHash('a'.repeat(64), 8)).toMatch(/^a{8}…a{6}$/)
  })
  it('builds a hex dump with printable ASCII', () => {
    const rows = hexDump('48 65 6c 6c 6f 00 ff')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ off: '0000', ascii: 'Hello..' })
  })
  it('splits hex dump into 16-byte rows', () => {
    expect(hexDump('00'.repeat(33))).toHaveLength(3)
  })
  it('joins truthy class names', () => {
    expect(cn('a', false, null, 'b')).toBe('a b')
  })
})
