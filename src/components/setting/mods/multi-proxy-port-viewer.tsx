import { AddRounded, DeleteRounded } from '@mui/icons-material'
import {
  Box,
  Button,
  IconButton,
  MenuItem,
  Select,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import yaml from 'js-yaml'
import type { Ref } from 'react'
import { useEffect, useImperativeHandle, useMemo, useState } from 'react'

import { BaseDialog } from '@/components/base'
import { useProfiles } from '@/hooks/use-profiles'
import { useVerge } from '@/hooks/use-verge'
import { useProxiesData } from '@/providers/app-data-context'
import { readProfileFile } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

export interface MultiProxyPortViewerRef {
  open: () => void
}

type Props = { ref?: Ref<MultiProxyPortViewerRef> }

const newListener = (
  index: number,
  profileUid = '',
  proxy = '',
): IMultiProxyListener => ({
  name: `proxy-${index + 1}`,
  type: 'mixed',
  port: 10080 + index,
  proxy,
  profile_uid: profileUid || undefined,
  listen: '127.0.0.1',
  udp: true,
  enabled: true,
})

export function MultiProxyPortViewer({ ref }: Props) {
  const { verge, patchVerge } = useVerge()
  const { profiles } = useProfiles()
  const { proxies } = useProxiesData()
  const [open, setOpen] = useState(false)
  const [items, setItems] = useState<IMultiProxyListener[]>([])
  const [loading, setLoading] = useState(false)
  const [profileTargets, setProfileTargets] = useState<
    Record<string, string[]>
  >({})

  const proxyTargets = useMemo(() => {
    const groups: IProxyGroupItem[] = proxies?.groups ?? []
    const names = groups.flatMap((group) => [
      group.name,
      ...group.all.map((item) => item.name),
    ])
    return [...new Set<string>(names.filter(Boolean))].sort((a, b) =>
      a.localeCompare(b),
    )
  }, [proxies])

  const selectableProfiles = useMemo(
    () =>
      (profiles?.items ?? []).filter(
        (profile) => profile.type === 'local' || profile.type === 'remote',
      ),
    [profiles],
  )

  useEffect(() => {
    let cancelled = false
    const loadTargets = async () => {
      const entries = await Promise.all(
        selectableProfiles.map(async (profile) => {
          try {
            const config = (yaml.load(await readProfileFile(profile.uid)) ??
              {}) as {
              proxies?: Array<{ name?: string }>
              'proxy-groups'?: Array<{ name?: string }>
            }
            const targets = [
              ...(config.proxies ?? []).map((item) => item.name),
              ...(config['proxy-groups'] ?? []).map((item) => item.name),
            ].filter((name): name is string => Boolean(name))
            return [profile.uid, targets] as const
          } catch {
            return [profile.uid, []] as const
          }
        }),
      )
      if (!cancelled) setProfileTargets(Object.fromEntries(entries))
    }
    void loadTargets()
    return () => {
      cancelled = true
    }
  }, [selectableProfiles])

  const targetsForProfile = (profileUid?: string) => {
    const uid = profileUid || profiles?.current
    const fromFile = uid ? (profileTargets[uid] ?? []) : []
    return [
      ...new Set(
        uid === profiles?.current ? [...proxyTargets, ...fromFile] : fromFile,
      ),
    ].sort((a, b) => a.localeCompare(b))
  }

  useImperativeHandle(ref, () => ({
    open: () => {
      setItems(verge?.multi_proxy_listeners ?? [])
      setOpen(true)
    },
  }))

  const updateItem = (index: number, patch: Partial<IMultiProxyListener>) => {
    setItems((current) =>
      current.map((item, itemIndex) =>
        itemIndex === index ? { ...item, ...patch } : item,
      ),
    )
  }

  const save = useLockFn(async () => {
    const names = new Set<string>()
    const ports = new Set<number>()
    for (const item of items) {
      if (!item.name.trim() || !item.proxy.trim()) {
        showNotice.error('每一项都需要名称和出口代理/策略组')
        return
      }
      if (!Number.isInteger(item.port) || item.port < 1 || item.port > 65535) {
        showNotice.error(`端口 “${item.name}” 必须在 1–65535 之间`)
        return
      }
      if (names.has(item.name) || ports.has(item.port)) {
        showNotice.error('监听名称和端口都不能重复')
        return
      }
      names.add(item.name)
      ports.add(item.port)
    }

    setLoading(true)
    try {
      await patchVerge({ multi_proxy_listeners: items })
      showNotice.success('多端口代理已保存，内核已重启应用新监听器')
      setOpen(false)
    } catch (error) {
      showNotice.error(error)
    } finally {
      setLoading(false)
    }
  })

  return (
    <BaseDialog
      open={open}
      title="多端口代理"
      contentSx={{ width: 720, maxWidth: 'calc(100vw - 32px)' }}
      okBtn="保存并重启内核"
      cancelBtn="取消"
      loading={loading}
      onOk={save}
      onClose={() => !loading && setOpen(false)}
      onCancel={() => !loading && setOpen(false)}
    >
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        每一行会创建一个 Mihomo
        listener；连接到该端口的流量会直接走所选节点或策略组，不再依赖全局规则。
      </Typography>
      <Typography
        variant="caption"
        color="warning.main"
        sx={{ display: 'block', mt: 1 }}
      >
        每一项可选择任意已导入配置；非当前配置会在运行时隔离合并，避免与主配置出现同名节点冲突。
      </Typography>

      <Stack spacing={1} sx={{ mt: 2 }}>
        {items.map((item, index) => (
          <Box
            key={`${item.name}-${item.port}`}
            sx={{
              display: 'grid',
              gridTemplateColumns: '1.1fr 1.4fr 92px 94px 1.3fr 118px 36px',
              gap: 1,
              alignItems: 'center',
            }}
          >
            <TextField
              size="small"
              label="名称"
              value={item.name}
              onChange={(event) =>
                updateItem(index, { name: event.target.value })
              }
            />
            <Select
              size="small"
              displayEmpty
              value={item.profile_uid ?? profiles?.current ?? ''}
              onChange={(event) =>
                updateItem(index, {
                  profile_uid: event.target.value || undefined,
                  proxy: '',
                })
              }
            >
              <MenuItem value="" disabled>
                选择配置
              </MenuItem>
              {selectableProfiles.map((profile) => (
                <MenuItem key={profile.uid} value={profile.uid}>
                  {profile.name || profile.uid}
                </MenuItem>
              ))}
            </Select>
            <Select
              size="small"
              value={item.type}
              onChange={(event) =>
                updateItem(index, {
                  type: event.target.value as IMultiProxyListener['type'],
                })
              }
            >
              <MenuItem value="mixed">Mixed</MenuItem>
              <MenuItem value="socks">SOCKS</MenuItem>
              <MenuItem value="http">HTTP</MenuItem>
            </Select>
            <TextField
              size="small"
              label="端口"
              type="number"
              value={item.port}
              onChange={(event) =>
                updateItem(index, { port: Number(event.target.value) })
              }
            />
            <Select
              size="small"
              displayEmpty
              value={item.proxy}
              onChange={(event) =>
                updateItem(index, { proxy: event.target.value })
              }
            >
              <MenuItem value="" disabled>
                选择出口
              </MenuItem>
              {targetsForProfile(item.profile_uid).map((target) => (
                <MenuItem key={target} value={target}>
                  {target}
                </MenuItem>
              ))}
            </Select>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Switch
                size="small"
                checked={item.enabled !== false}
                onChange={(_, enabled) => updateItem(index, { enabled })}
              />
              <Typography variant="caption">启用</Typography>
            </Box>
            <IconButton
              size="small"
              title="删除"
              onClick={() =>
                setItems((current) => current.filter((_, i) => i !== index))
              }
            >
              <DeleteRounded fontSize="small" />
            </IconButton>
          </Box>
        ))}
      </Stack>

      <Button
        size="small"
        startIcon={<AddRounded />}
        sx={{ mt: 1.5 }}
        onClick={() =>
          setItems((current) => [
            ...current,
            newListener(
              current.length,
              profiles?.current,
              targetsForProfile(profiles?.current)[0],
            ),
          ])
        }
      >
        添加端口
      </Button>
    </BaseDialog>
  )
}
