import type { Plugin, PluginOptions as OpenCodePluginOptions } from '@opencode-ai/plugin'

export type PluginClient = Parameters<Plugin>[0]['client']

export type PluginContext = Parameters<Plugin>[0]

export type PluginOptions = OpenCodePluginOptions

export type PluginResult = Awaited<ReturnType<Plugin>>
