import { ContentPasteRounded } from '@mui/icons-material'
import { Box, Button, TextField, Typography } from '@mui/material'
import { readText } from '@tauri-apps/plugin-clipboard-manager'
import { useLockFn } from 'ahooks'
import type { ChangeEvent, Ref } from 'react'
import { useImperativeHandle, useRef, useState } from 'react'

import { BaseDialog } from '@/components/base'
import { createProfile } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'
import { importDirectProxySource } from '@/utils/direct-proxy-import'

export interface DirectProxyImportViewerRef {
  open: () => void
}

interface Props {
  onImported: (isActivating: boolean) => Promise<void> | void
  isFirstProfile: boolean
  ref?: Ref<DirectProxyImportViewerRef>
}

export function DirectProxyImportViewer({
  onImported,
  isFirstProfile,
  ref,
}: Props) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [source, setSource] = useState('')
  const [loading, setLoading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useImperativeHandle(ref, () => ({
    open: () => setOpen(true),
  }))

  const close = () => {
    if (loading) return
    setOpen(false)
    setName('')
    setSource('')
  }

  const finishImport = () => {
    setOpen(false)
    setName('')
    setSource('')
  }

  const readFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    try {
      setSource(await file.text())
      if (!name.trim()) setName(file.name.replace(/\.[^.]+$/, ''))
    } catch (error) {
      showNotice.error(error)
    }
  }

  const pasteClipboard = async () => {
    try {
      const clipboardText = await readText()
      if (!clipboardText?.trim()) {
        throw new Error('剪贴板中没有可导入的文本')
      }
      setSource(clipboardText)
    } catch (error) {
      showNotice.error(error)
    }
  }

  const importSource = useLockFn(async () => {
    setLoading(true)
    try {
      const result = importDirectProxySource(source, name)
      await createProfile(
        {
          type: 'local',
          name: result.profileName,
          desc: `图形导入：${result.proxyCount} 个节点`,
        },
        result.yaml,
      )
      showNotice.success(`已导入 ${result.proxyCount} 个节点`)
      if (result.warnings.length) {
        showNotice.info(`转换提示：${result.warnings.join(' ')}`, 9000)
      }
      finishImport()
      await onImported(isFirstProfile)
    } catch (error) {
      showNotice.error(error)
    } finally {
      setLoading(false)
    }
  })

  return (
    <BaseDialog
      open={open}
      title="导入节点 / 配置 JSON"
      contentSx={{ width: 560, maxWidth: 'calc(100vw - 32px)' }}
      okBtn="导入"
      cancelBtn="取消"
      loading={loading}
      onOk={importSource}
      onCancel={close}
      onClose={close}
    >
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        可从剪贴板导入 VLESS、VMess、Trojan、SS、Hysteria2、TUIC 等链接（多行或
        Base64 订阅内容），也支持 Clash/Mihomo YAML、sing-box
        JSON，以及常见客户端导出的单节点 JSON（含
        VLESS、VMess、Trojan、SS），并会保留 VLESS 的
        XTLS/Vision、Reality、TLS、SNI、ALPN
        与常见传输参数。无法无损转换的关键字段会阻止导入，不会静默丢弃。
      </Typography>
      <Typography
        variant="caption"
        color="warning.main"
        sx={{ display: 'block', mt: 1 }}
      >
        sing-box 的
        DNS、入站/TUN、路由和规则集不会被静默转换；导入后会显示未迁移项。
      </Typography>
      <TextField
        autoFocus
        fullWidth
        size="small"
        label="配置名称（可选）"
        value={name}
        onChange={(event) => setName(event.target.value)}
        sx={{ mt: 2 }}
      />
      <TextField
        fullWidth
        multiline
        minRows={12}
        maxRows={18}
        label="节点链接或 JSON 配置"
        value={source}
        onChange={(event) => setSource(event.target.value)}
        sx={{ mt: 2 }}
      />
      <Box sx={{ mt: 1 }}>
        <input
          ref={fileInputRef}
          type="file"
          accept=".json,.txt,.yaml,.yml"
          hidden
          onChange={readFile}
        />
        <Button
          size="small"
          startIcon={<ContentPasteRounded />}
          onClick={pasteClipboard}
        >
          从剪贴板导入
        </Button>
        <Button size="small" onClick={() => fileInputRef.current?.click()}>
          选择 JSON / 文本文件
        </Button>
      </Box>
    </BaseDialog>
  )
}
