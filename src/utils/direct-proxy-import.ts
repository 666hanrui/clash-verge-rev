import yaml from 'js-yaml'

import parseUri from '@/utils/uri-parser'

type JsonRecord = Record<string, unknown>

export interface DirectProxyImport {
  profileName: string
  yaml: string
  proxyCount: number
  warnings: string[]
}

interface ClientNodeMapping {
  proxy: IProxyConfig
  warnings: string[]
}

const asRecord = (value: unknown): JsonRecord | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined

const asString = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim() ? value.trim() : undefined

const asPort = (value: unknown): number | undefined => {
  const port = typeof value === 'number' ? value : Number(value)
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : undefined
}

const asInteger = (value: unknown): number | undefined => {
  const integer = typeof value === 'number' ? value : Number(value)
  return Number.isInteger(integer) ? integer : undefined
}

const asStringArray = (value: unknown): string[] | undefined => {
  if (!Array.isArray(value)) return undefined
  const values = value
    .map(asString)
    .filter((item): item is string => Boolean(item))
  return values.length ? values : undefined
}

const asBoolean = (value: unknown): boolean | undefined => {
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  if (typeof value === 'string') {
    if (['true', '1', 'yes'].includes(value.trim().toLowerCase())) return true
    if (['false', '0', 'no'].includes(value.trim().toLowerCase())) return false
  }
  return undefined
}

const splitTextList = (value: unknown): string[] | undefined => {
  const text = asString(value)
  if (!text) return undefined
  const values = text
    .split(/[,;]+/)
    .map((item) => item.trim())
    .filter(Boolean)
  return values.length ? values : undefined
}

const uniqueName = (base: string, used: Set<string>) => {
  const trimmed = base.trim() || 'Imported proxy'
  if (!used.has(trimmed)) {
    used.add(trimmed)
    return trimmed
  }

  let suffix = 2
  while (used.has(`${trimmed} ${suffix}`)) suffix += 1
  const name = `${trimmed} ${suffix}`
  used.add(name)
  return name
}

function mapSingBoxTls(proxy: JsonRecord, tlsValue: unknown) {
  const tls = asRecord(tlsValue)
  if (!tls || tls.enabled !== true) return

  proxy.tls = true
  proxy.servername = asString(tls.server_name)
  if (typeof tls.insecure === 'boolean') {
    proxy['skip-cert-verify'] = tls.insecure
  }
  const alpn = asStringArray(tls.alpn)
  if (alpn) proxy.alpn = alpn

  const utls = asRecord(tls.utls)
  const fingerprint = asString(utls?.fingerprint)
  if (utls?.enabled === true && fingerprint) {
    proxy['client-fingerprint'] = fingerprint
  }
}

function mapSingBoxTransport(proxy: JsonRecord, transportValue: unknown) {
  const transport = asRecord(transportValue)
  const type = asString(transport?.type)
  if (!transport || !type || type === 'tcp') return

  if (type === 'ws') {
    proxy.network = 'ws'
    const opts: JsonRecord = {}
    const path = asString(transport.path)
    const headers = asRecord(transport.headers)
    if (path) opts.path = path
    if (headers && Object.keys(headers).length) opts.headers = headers
    if (Object.keys(opts).length) proxy['ws-opts'] = opts
    return
  }

  if (type === 'grpc') {
    proxy.network = 'grpc'
    const serviceName = asString(transport.service_name)
    if (serviceName) {
      proxy['grpc-opts'] = { 'grpc-service-name': serviceName }
    }
    return
  }

  if (type === 'http') {
    proxy.network = 'h2'
    const opts: JsonRecord = {}
    const host = asStringArray(transport.host)
    const path = asString(transport.path)
    if (host) opts.host = host
    if (path) opts.path = path
    if (Object.keys(opts).length) proxy['h2-opts'] = opts
  }
}

function mapSingBoxOutbound(outbound: JsonRecord, index: number): IProxyConfig {
  const type = asString(outbound.type)
  const server = asString(outbound.server)
  const port = asPort(outbound.server_port)
  const name = asString(outbound.tag) ?? `${type ?? 'proxy'} ${index + 1}`

  if (!type || !server || !port) {
    throw new Error(`第 ${index + 1} 个出站缺少 type、server 或 server_port`)
  }

  const proxy: JsonRecord = {
    name,
    type: type === 'shadowsocks' ? 'ss' : type,
    server,
    port,
  }
  switch (type) {
    case 'vless': {
      const uuid = asString(outbound.uuid)
      if (!uuid) throw new Error(`VLESS 节点 “${name}” 缺少 uuid`)
      proxy.uuid = uuid
      proxy.encryption = asString(outbound.encryption) ?? ''
      const flow = asString(outbound.flow)
      if (flow) proxy.flow = flow
      break
    }
    case 'vmess': {
      const uuid = asString(outbound.uuid)
      if (!uuid) throw new Error(`VMess 节点 “${name}” 缺少 uuid`)
      proxy.uuid = uuid
      proxy.cipher = asString(outbound.security) ?? 'auto'
      proxy.alterId =
        typeof outbound.alter_id === 'number' ? outbound.alter_id : 0
      break
    }
    case 'trojan': {
      const password = asString(outbound.password)
      if (!password) throw new Error(`Trojan 节点 “${name}” 缺少 password`)
      proxy.password = password
      break
    }
    case 'shadowsocks': {
      const method = asString(outbound.method)
      const password = asString(outbound.password)
      if (!method || !password) {
        throw new Error(`Shadowsocks 节点 “${name}” 缺少 method 或 password`)
      }
      proxy.cipher = method
      proxy.password = password
      break
    }
    case 'hysteria2': {
      const password = asString(outbound.password)
      if (!password) throw new Error(`Hysteria2 节点 “${name}” 缺少 password`)
      proxy.password = password
      const obfs = asRecord(outbound.obfs)
      if (asString(obfs?.type) && asString(obfs?.type) !== 'none') {
        proxy.obfs = asString(obfs?.type)
        proxy['obfs-password'] = asString(obfs?.password)
      }
      proxy.sni = asString(asRecord(outbound.tls)?.server_name)
      break
    }
    case 'tuic': {
      const uuid = asString(outbound.uuid)
      const password = asString(outbound.password)
      if (!uuid || !password) {
        throw new Error(`TUIC 节点 “${name}” 缺少 uuid 或 password`)
      }
      proxy.uuid = uuid
      proxy.password = password
      proxy.sni = asString(asRecord(outbound.tls)?.server_name)
      proxy['congestion-controller'] = asString(outbound.congestion_control)
      proxy['udp-relay-mode'] = asString(outbound.udp_relay_mode)
      break
    }
    case 'http':
    case 'socks': {
      proxy.type = type === 'socks' ? 'socks5' : 'http'
      proxy.username = asString(outbound.username)
      proxy.password = asString(outbound.password)
      break
    }
    default:
      throw new Error(`暂不支持将 sing-box ${type} 出站转换为 Mihomo 节点`)
  }

  if (typeof outbound.udp_over_tcp === 'boolean') {
    proxy['udp-over-tcp'] = outbound.udp_over_tcp
  }
  if (['vless', 'vmess', 'trojan'].includes(type)) {
    mapSingBoxTls(proxy, outbound.tls)
    mapSingBoxTransport(proxy, outbound.transport)
  } else if (['hysteria2', 'tuic'].includes(type)) {
    const tls = asRecord(outbound.tls)
    if (typeof tls?.insecure === 'boolean') {
      proxy['skip-cert-verify'] = tls.insecure
    }
    const alpn = asStringArray(tls?.alpn)
    if (alpn) proxy.alpn = alpn
    const fingerprint = asString(asRecord(tls?.utls)?.fingerprint)
    if (fingerprint) proxy.fingerprint = fingerprint
  }
  return proxy as unknown as IProxyConfig
}

/**
 * Converts the flattened node JSON exported by clients such as Shadowrocket,
 * V2RayU and similar mobile/desktop managers.  It is not a sing-box config:
 * its connection details are stored directly on the root object (host, port,
 * password, peer, tlsProfile, ...).
 */
function mapClientNodeJson(node: JsonRecord, index: number): ClientNodeMapping {
  const type = asString(node.type)?.toLowerCase()
  const server =
    asString(node.host) ?? asString(node.server) ?? asString(node.ip)
  const port = asPort(node.port)
  const name =
    asString(node.title) ??
    asString(node.name) ??
    `${type ?? 'proxy'} ${index + 1}`

  if (!type || !server || !port) {
    throw new Error(`第 ${index + 1} 个节点缺少 type、host 或 port`)
  }

  const normalizedType = type === 'shadowsocks' ? 'ss' : type
  const proxy: JsonRecord = { name, type: normalizedType, server, port }
  const warnings: string[] = []
  const password = asString(node.password)
  // Flattened client JSON often stores its local record identifier in `uuid`
  // and the actual VLESS/VMess credential in `password`.
  const credentialUuid = password ?? asString(node.uuid)
  const nodeUuid = asString(node.uuid)
  const tls = asBoolean(node.tls)

  switch (normalizedType) {
    case 'vless':
      if (!credentialUuid)
        throw new Error(`VLESS 节点 “${name}” 缺少 password/uuid`)
      proxy.uuid = credentialUuid
      proxy.encryption =
        asString(node.method) ?? asString(node.encryption) ?? 'none'
      break
    case 'vmess':
      if (!credentialUuid)
        throw new Error(`VMess 节点 “${name}” 缺少 password/uuid`)
      proxy.uuid = credentialUuid
      proxy.alterId = Number(asString(node.alterId) ?? 0) || 0
      proxy.cipher = asString(node.method) ?? asString(node.security) ?? 'auto'
      break
    case 'trojan':
      if (!password) throw new Error(`Trojan 节点 “${name}” 缺少 password`)
      proxy.password = password
      break
    case 'ss':
      if (!password) throw new Error(`Shadowsocks 节点 “${name}” 缺少 password`)
      proxy.cipher = asString(node.method) ?? 'aes-128-gcm'
      proxy.password = password
      break
    case 'hysteria2':
    case 'hy2':
      if (!password) throw new Error(`Hysteria2 节点 “${name}” 缺少 password`)
      proxy.type = 'hysteria2'
      proxy.password = password
      break
    case 'tuic':
      if (!nodeUuid || !password)
        throw new Error(`TUIC 节点 “${name}” 缺少 uuid 或 password`)
      proxy.uuid = nodeUuid
      proxy.password = password
      break
    case 'http':
    case 'https':
      proxy.type = 'http'
      proxy.username = asString(node.user) ?? asString(node.username)
      proxy.password = password
      break
    case 'socks':
    case 'socks5':
      proxy.type = 'socks5'
      proxy.username = asString(node.user) ?? asString(node.username)
      proxy.password = password
      break
    default:
      throw new Error(`暂不支持 JSON 节点类型 “${type}”`)
  }

  if (tls !== undefined) proxy.tls = tls
  const servername = asString(node.peer) ?? asString(node.sni)
  if (servername) proxy.servername = servername
  const alpn = splitTextList(node.alpn)
  if (alpn) proxy.alpn = alpn
  const fingerprint = asString(node.tlsProfile) ?? asString(node.fingerprint)
  if (fingerprint) proxy['client-fingerprint'] = fingerprint
  const udp = asBoolean(node.udp)
  if (udp !== undefined) proxy.udp = udp

  // Shadowrocket-style exports encode VLESS XTLS flow as a numeric `xtls`
  // field. This is a connection requirement, not optional metadata: ignoring
  // it produces a syntactically valid profile that cannot complete a session.
  const explicitFlow = asString(node.flow)
  const hasXtls =
    node.xtls !== undefined &&
    node.xtls !== null &&
    `${node.xtls}`.trim() !== ''
  const xtls = hasXtls ? asInteger(node.xtls) : undefined
  if (hasXtls && xtls === undefined) {
    throw new Error(
      `VLESS 节点 “${name}” 的 xtls 值无法识别，已停止导入以避免生成错误配置`,
    )
  }
  const xtlsFlow =
    xtls === undefined || xtls === 0
      ? undefined
      : xtls === 1
        ? 'xtls-rprx-direct'
        : xtls === 2
          ? 'xtls-rprx-vision'
          : undefined
  if (xtls !== undefined && !xtlsFlow && xtls !== 0) {
    throw new Error(
      `VLESS 节点 “${name}” 使用了未支持的 xtls=${xtls}，已停止导入以避免连接语义丢失`,
    )
  }
  if (explicitFlow && xtlsFlow && explicitFlow !== xtlsFlow) {
    throw new Error(
      `VLESS 节点 “${name}” 的 flow 与 xtls 定义冲突，无法安全导入`,
    )
  }
  const flow = explicitFlow ?? xtlsFlow
  if (flow) {
    if (normalizedType !== 'vless') {
      throw new Error(`节点 “${name}” 使用 flow/xtls，但它只适用于 VLESS`)
    }
    if (tls !== true) {
      throw new Error(
        `VLESS 节点 “${name}” 使用 ${flow}，但未明确启用 tls；已停止导入`,
      )
    }
    proxy.flow = flow
  }

  // A public key identifies VLESS Reality. Keep all Reality parameters rather
  // than silently treating it as ordinary TLS. Mihomo requires a uTLS
  // fingerprint for Reality; use the widely compatible chrome default only
  // when the source export omitted it, and surface that choice to the user.
  const publicKey = asString(node.publicKey) ?? asString(node['public-key'])
  const shortId = asString(node.shortId) ?? asString(node['short-id'])
  if (publicKey) {
    if (normalizedType !== 'vless') {
      throw new Error(
        `节点 “${name}” 包含 Reality publicKey，但不是 VLESS，无法安全导入`,
      )
    }
    if (tls !== true) {
      throw new Error(`VLESS Reality 节点 “${name}” 未明确启用 tls，已停止导入`)
    }
    proxy.tls = true
    proxy['reality-opts'] = {
      'public-key': publicKey,
      ...(shortId ? { 'short-id': shortId } : {}),
    }
    if (!fingerprint) {
      proxy['client-fingerprint'] = 'chrome'
      warnings.push(
        `节点 “${name}” 是 Reality，但未提供 tlsProfile；已使用 chrome 指纹。`,
      )
    }
  }

  const unsupportedFeatures: Array<[unknown, string]> = [
    [node.ech, 'ECH'],
    [node.chain, '代理链'],
    [node.plugin, '插件传输'],
  ]
  for (const [value, feature] of unsupportedFeatures) {
    if (asString(value)) {
      throw new Error(
        `节点 “${name}” 使用 ${feature}，当前版本无法无损转换，未创建该节点`,
      )
    }
  }

  const network = (
    asString(node.obfs) ??
    asString(node.network) ??
    'none'
  ).toLowerCase()
  const path = asString(node.path)
  const obfsParam = asString(node.obfsParam)
  if (network === 'ws' || network === 'websocket') {
    proxy.network = 'ws'
    const headers: JsonRecord = {}
    const host = asString(node.hostHeader) ?? obfsParam
    if (host) headers.Host = host
    proxy['ws-opts'] = {
      ...(path ? { path } : {}),
      ...(Object.keys(headers).length ? { headers } : {}),
    }
  } else if (network === 'grpc') {
    proxy.network = 'grpc'
    const serviceName = obfsParam ?? path
    if (serviceName) proxy['grpc-opts'] = { 'grpc-service-name': serviceName }
  } else if (network === 'http' || network === 'h2') {
    proxy.network = 'h2'
    proxy['h2-opts'] = {
      ...(path ? { path } : {}),
      ...(obfsParam ? { host: splitTextList(obfsParam) ?? [obfsParam] } : {}),
    }
  } else if (!['none', 'tcp', 'plain'].includes(network)) {
    throw new Error(
      `节点 “${name}” 使用未支持的传输方式 obfs=${network}，未创建该节点`,
    )
  }

  return { proxy: proxy as unknown as IProxyConfig, warnings }
}

function decodeSubscription(input: string) {
  try {
    const decoded = atob(input.replace(/\s/g, ''))
    return /(^[a-z][a-z\d+.-]*:\/\/)|(^\s*[{[])|(^|\n)\s*(proxies|proxy-groups):/im.test(
      decoded,
    )
      ? decoded
      : input
  } catch {
    return input
  }
}

function importClashYaml(
  config: JsonRecord,
  requestedName?: string,
): DirectProxyImport {
  const proxies = Array.isArray(config.proxies)
    ? config.proxies
        .map(asRecord)
        .filter((proxy): proxy is JsonRecord => Boolean(proxy))
        .filter((proxy) => asString(proxy.name) && asString(proxy.type))
        .map((proxy) => ({ ...proxy }) as unknown as IProxyConfig)
    : []
  if (!proxies.length) {
    throw new Error('Clash/Mihomo YAML 中没有可导入的 proxies 节点')
  }
  const warnings: string[] = []
  if (config['proxy-providers']) {
    warnings.push(
      'YAML 中的 proxy-providers 未复制；已导入其内联 proxies 节点。',
    )
  }
  if (config.rules || config['rule-providers'] || config.dns || config.tun) {
    warnings.push(
      'YAML 的规则、DNS、TUN 等全局设置未迁移；将使用 Clash Verge 当前设置。',
    )
  }
  return {
    profileName:
      requestedName?.trim() || proxies[0].name || 'Imported Clash YAML',
    yaml: createProfileYaml(proxies),
    proxyCount: proxies.length,
    warnings,
  }
}

function createProfileYaml(proxies: IProxyConfig[]) {
  const usedNames = new Set<string>()
  const normalized = proxies.map((proxy) => ({
    ...proxy,
    name: uniqueName(proxy.name, usedNames),
  }))
  const groupName = uniqueName('Imported', usedNames)
  return yaml.dump(
    {
      proxies: normalized,
      'proxy-groups': [
        {
          name: groupName,
          type: 'select',
          proxies: [...normalized.map((p) => p.name), 'DIRECT'],
        },
      ],
      rules: [`MATCH,${groupName}`],
    },
    { noRefs: true, lineWidth: -1 },
  )
}

function importSingBoxConfig(
  config: JsonRecord,
  requestedName?: string,
): DirectProxyImport {
  const outbounds = Array.isArray(config.outbounds) ? config.outbounds : []
  const warnings: string[] = []
  const proxies: IProxyConfig[] = []

  outbounds.forEach((value, index) => {
    const outbound = asRecord(value)
    const type = asString(outbound?.type)
    if (
      !outbound ||
      ['direct', 'block', 'dns', 'selector', 'urltest'].includes(type ?? '')
    ) {
      return
    }
    try {
      proxies.push(mapSingBoxOutbound(outbound, index))
    } catch (error) {
      warnings.push(error instanceof Error ? error.message : String(error))
    }
  })

  if (!proxies.length) {
    throw new Error('JSON 中没有可转换的 sing-box出站节点')
  }
  if (config.dns)
    warnings.push('sing-box DNS 配置未迁移；将使用 Clash Verge 当前 DNS 设置。')
  if (config.inbounds)
    warnings.push(
      'sing-box 入站（含 TUN 和本地端口）未迁移；请在应用设置中配置端口和 TUN。',
    )
  if (config.route)
    warnings.push(
      'sing-box 路由和规则集未迁移；生成的本地配置默认将流量交给导入节点。',
    )

  return {
    profileName:
      requestedName?.trim() ||
      asString(proxies[0]?.name) ||
      'Imported sing-box',
    yaml: createProfileYaml(proxies),
    proxyCount: proxies.length,
    warnings,
  }
}

function importClientNodeJson(
  nodes: JsonRecord[],
  requestedName?: string,
): DirectProxyImport {
  const warnings: string[] = []
  const proxies: IProxyConfig[] = []
  nodes.forEach((node, index) => {
    try {
      const mapped = mapClientNodeJson(node, index)
      proxies.push(mapped.proxy)
      warnings.push(...mapped.warnings)
    } catch (error) {
      warnings.push(error instanceof Error ? error.message : String(error))
    }
  })
  if (!proxies.length) {
    throw new Error(warnings[0] ?? 'JSON 中没有可转换的节点')
  }
  return {
    profileName:
      requestedName?.trim() || proxies[0].name || 'Imported JSON nodes',
    yaml: createProfileYaml(proxies),
    proxyCount: proxies.length,
    warnings,
  }
}

export function importDirectProxySource(
  source: string,
  requestedName?: string,
): DirectProxyImport {
  const input = decodeSubscription(source.trim())
  if (!input) throw new Error('请输入节点链接、订阅内容或 sing-box JSON')

  try {
    const parsed = JSON.parse(input)
    const config = asRecord(parsed)
    if (config?.outbounds) return importSingBoxConfig(config, requestedName)
    const nodeList = Array.isArray(parsed)
      ? parsed.map(asRecord).filter((node): node is JsonRecord => Boolean(node))
      : config
        ? [config]
        : []
    if (
      nodeList.some(
        (node) =>
          asString(node.type) && (asString(node.host) || asString(node.server)),
      )
    ) {
      return importClientNodeJson(nodeList, requestedName)
    }
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error
  }

  try {
    const parsed = yaml.load(input)
    const config = asRecord(parsed)
    if (config?.proxies) return importClashYaml(config, requestedName)
  } catch (error) {
    if (input.includes('proxies:')) throw error
  }

  const usedNames = new Set<string>()
  const errors: string[] = []
  const proxies = decodeSubscription(input)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      try {
        const proxy = parseUri(line)
        return [{ ...proxy, name: uniqueName(proxy.name, usedNames) }]
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error))
        return []
      }
    })

  if (!proxies.length) {
    throw new Error(errors[0] ?? '未识别到支持的代理链接')
  }

  return {
    profileName: requestedName?.trim() || proxies[0].name || 'Imported proxies',
    yaml: createProfileYaml(proxies),
    proxyCount: proxies.length,
    warnings: errors.length
      ? [`已跳过 ${errors.length} 条无法识别的链接。`]
      : [],
  }
}
