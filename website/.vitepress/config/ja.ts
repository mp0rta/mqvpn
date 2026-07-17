import { DefaultTheme, LocaleSpecificConfig } from 'vitepress'

export const ja: LocaleSpecificConfig<DefaultTheme.Config> & { label: string; lang: string } = {
  label: '日本語',
  lang: 'ja',
  description: 'オープン標準上に構築されたモダンなマルチパス VPN',

  themeConfig: {
    nav: [
      { text: 'ガイド', link: '/ja/guide/getting-started' },
      { text: 'ベンチマーク', link: '/ja/benchmarks/' },
    ],

    footer: {
      message: 'Apache License 2.0 に基づき公開',
      copyright: '本ソフトウェアは現状有姿（AS IS）で提供され、いかなる保証も行いません。利用は自己責任で行ってください。',
    },

    sidebar: {
      '/ja/benchmarks/': [
        {
          text: 'ベンチマーク',
          items: [
            { text: '概要', link: '/ja/benchmarks/' },
            { text: 'Per-commit', link: '/ja/benchmarks/per-commit' },
            { text: 'Weekly', link: '/ja/benchmarks/weekly' },
          ],
        },
      ],
      '/ja/guide/': [
        {
          text: 'ガイド',
          items: [
            { text: 'はじめに', link: '/ja/guide/getting-started' },
            { text: 'ビルド', link: '/ja/guide/building' },
            { text: '設定', link: '/ja/guide/configuration' },
            { text: 'マルチパス', link: '/ja/guide/multipath' },
            { text: 'ハイブリッドモード', link: '/ja/guide/hybrid-mode' },
            { text: 'アーキテクチャ', link: '/ja/guide/architecture' },
          ],
        },
      ],
    },
  },
}
