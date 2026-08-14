import { LanRounded, PowerSettingsNewRounded } from '@mui/icons-material'
import {
  Box,
  Chip,
  MenuItem,
  Select,
  Switch,
  TextField,
  Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import yaml from 'js-yaml'
import { useEffect, useMemo, useState } from 'react'

import { useVerge } from '@/hooks/use-verge'
import { readProfileFile } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

interface Props {
  profile: IProfileItem
}

const listenerName = (uid: string) => `profile-${uid.slice(0, 8)}`

export function ProfilePortControls({ profile }: Props) {
  const { verge, patchVerge } = useVerge()
  const [targets, setTargets] = useState<string[]>([])
  const listeners = useMemo(
    () => verge?.multi_proxy_listeners ?? [],
    [verge?.multi_proxy_listeners],
  )
  const listener = useMemo(
    () => listeners.find((item) => item.profile_uid === profile.uid),
    [listeners, profile.uid],
  )

  useEffect(() => {
    let cancelled = false
    void readProfileFile(profile.uid)
      .then((content) => {
        const config = (yaml.load(content) ?? {}) as {
          proxies?: Array<{ name?: string }>
          'proxy-groups'?: Array<{ name?: string }>
        }
        const names = [
          ...(config['proxy-groups'] ?? []).map((item) => item.name),
          ...(config.proxies ?? []).map((item) => item.name),
        ].filter((item): item is string => Boolean(item))
        if (!cancelled) setTargets([...new Set(names)])
      })
      .catch(() => !cancelled && setTargets([]))
    return () => {
      cancelled = true
    }
  }, [profile.uid])

  const update = useLockFn(async (patch: Partial<IMultiProxyListener>) => {
    const index = listeners.findIndex(
      (item) => item.profile_uid === profile.uid,
    )
    const fallbackTarget = targets[0]
    if (index < 0 && !fallbackTarget) {
      showNotice.error('这个订阅没有可用节点，无法创建独立代理端口')
      return
    }
    const next = [...listeners]
    const nextItem: IMultiProxyListener = {
      name: listenerName(profile.uid),
      type: 'mixed',
      port: 10080 + listeners.length,
      proxy: fallbackTarget ?? '',
      profile_uid: profile.uid,
      listen: '127.0.0.1',
      udp: true,
      enabled: true,
      ...patch,
    }
    if (index < 0) next.push(nextItem)
    else next[index] = { ...next[index], ...patch }
    await patchVerge({ multi_proxy_listeners: next })
  })

  const toggleSystemProxy = useLockFn(async (enabled: boolean) => {
    if (!listener) {
      await update({ enabled: true })
    }
    const active = listener ?? {
      name: listenerName(profile.uid),
      type: 'mixed' as const,
      port: 10080 + listeners.length,
      listen: '127.0.0.1',
    }
    if (active.type === 'socks') {
      showNotice.error('系统代理需要 HTTP 或 Mixed 协议端口')
      return
    }
    await patchVerge({
      enable_system_proxy: enabled,
      system_proxy_listener: enabled ? active.name : undefined,
      proxy_auto_config: false,
      proxy_host: active.listen ?? '127.0.0.1',
    })
    if (enabled) showNotice.success('已设为系统代理；同一时间只能启用一个订阅')
  })

  const enabled = listener?.enabled !== false
  const systemProxyActive =
    verge?.enable_system_proxy === true &&
    verge.system_proxy_listener === listener?.name

  return (
    <Box
      onClick={(event) => event.stopPropagation()}
      sx={{ mt: 1.25, pt: 1, borderTop: '1px dashed', borderColor: 'divider' }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.75 }}>
        <LanRounded fontSize="small" color="primary" />
        <Typography variant="caption" sx={{ fontWeight: 700 }}>
          独立端口代理
        </Typography>
        <Chip
          size="small"
          label={listener ? listener.type.toUpperCase() : '未配置'}
          color={enabled && listener ? 'primary' : 'default'}
          sx={{ height: 20 }}
        />
        <Typography variant="caption" color="text.secondary">
          {listener ? `127.0.0.1:${listener.port}` : '启用后自动分配端口'}
        </Typography>
      </Box>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 0.75,
          flexWrap: 'wrap',
        }}
      >
        <Switch
          size="small"
          checked={enabled && Boolean(listener)}
          onChange={(_, value) => void update({ enabled: value })}
        />
        <Typography variant="caption">启用代理</Typography>
        {listener && (
          <>
            <Select
              size="small"
              value={listener.type}
              onChange={(event) =>
                void update({
                  type: event.target.value as IMultiProxyListener['type'],
                })
              }
              sx={{ minWidth: 88, height: 30 }}
            >
              <MenuItem value="mixed">Mixed</MenuItem>
              <MenuItem value="http">HTTP</MenuItem>
              <MenuItem value="socks">SOCKS</MenuItem>
            </Select>
            <TextField
              size="small"
              label="端口"
              type="number"
              value={listener.port}
              onChange={(event) =>
                void update({ port: Number(event.target.value) })
              }
              sx={{ width: 100 }}
            />
          </>
        )}
        <Box
          sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 0.25 }}
        >
          <PowerSettingsNewRounded
            fontSize="small"
            color={systemProxyActive ? 'success' : 'disabled'}
          />
          <Typography variant="caption">系统代理</Typography>
          <Switch
            size="small"
            checked={systemProxyActive}
            disabled={!listener || !enabled || listener.type === 'socks'}
            onChange={(_, value) => void toggleSystemProxy(value)}
          />
        </Box>
      </Box>
      <Typography variant="caption" color="text.secondary">
        系统代理一次只能选择一个订阅；此订阅的流量将直接使用上方当前协议端口。
      </Typography>
    </Box>
  )
}
