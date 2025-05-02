# mediaX

mediaX 是一款使用 Go 语言开发的个人阅读/观影/看剧/追番/游戏记录 Web 管理工具。

**特点：**

- Go 原生 Web 开发，无外部框架
- 轻量，简单，无任何 JavaScript 代码
- 数据库使用 SQLite + 纯 Go 实现的驱动 [glebarez/sqlite](https://github.com/glebarez/sqlite)，无 CGO 依赖
- 支持从豆瓣或 Bangumi 导入已有历史记录
- 支持新增条目时自动从豆瓣或 Bangumi 获取数据
- 支持导出内部记录为 JSON 数据

[查看详细介绍](https://atpx.com/blog/go-mediax)

\* *该项目主要是为了满足个人学习和使用需要，暂不接受新功能建议，如果有额外功能需求欢迎 fork 修改（MIT 协议）。*

## 使用说明

mediaX 从 [v0.6.0](https://github.com/bitterspread/mediax/releases/tag/v0.6.0) 版本开始通过配置文件启动，默认加载程序目录下的 `config.json` 文件，也可通过 `--config` 参数指定。配置文件格式如下：
```json
{
    "server": {
        "address": "0.0.0.0",
        "port": 8080,
        "use_https": false
    },
    "user": {
        "username": "username",
        "password": "{bcrypt}$2a$password"
    },
    "session_timeout": "168h",
    "categories": ["book", "movie", "tv", "anime", "game"],
    "pagination": {
        "page_size": 10
    },
    "api_key": ""
}
```

其中：

- address: 监听地址，默认 0.0.0.0
- port: 监听端口，默认 8080
- use_https: 启用安全连接，默认 false，建议在 HTTPS 环境下开启
- username: 用户名，限制 1 至 64 个字符
- password: 密码，限制 4 至 64 个字符
- session_timeout: 登录过期时间，默认 168h（7天）
- categories: 开启的分类模块，默认全部开启
- page_size: 分页条目数量，限制 10 至 50 长度
- api_key: 默认为空，不启用 API 功能

配置文件中用户名和密码不能为空，且密码使用 BCrypt 加密，可使用 `--bcrypt` 参数加密，例如：
```bash
# 设置密码: hubcap-oxidation-album-glitzy-tying
# Linux / macOS
./mediax --bcrypt "hubcap-oxidation-album-glitzy-tying"
# Windows
mediax.exe --bcrypt "hubcap-oxidation-album-glitzy-tying"

# 输出:
{bcrypt}$2a$10$kR.uXEAfE.ADUoGd5SaXqu75HjGwzSdmi2rbFHX/OT8DrkoltS7a6
```

将输出的值填入配置文件 `password` 字段中即可。

mediaX 支持导入豆瓣（图书/电影/剧集）或 [Bangumi 番组计划](https://bgm.tv/)（图书/电影/剧集/番剧/游戏）数据来源的个人历史记录，其中 Bangumi 的电影和剧集记录因 API 返回内容限制未做详细区分，简单的判断如果只有一集归类为电影，大于一集则归类为剧集。

- 导入豆瓣数据：首先使用「[豆伴](https://github.com/doufen-org/tofu)」导出数据，安装好插件后，进入设置连接账号，然后点击浏览器任务栏插件图标选择 `新建任务`，选择备份的项目中只勾选第一个 **影/音/书/游/剧**，等待任务完成后，点击右上方 `浏览备份` - `备份数据库`，解压下载的文件，其中的 `tofu[xxxxxx].json` 为需要的文件。
- 导入 Bangumi 数据：可以直接使用 Bangumi 提供的 [API](https://bangumi.github.io/api/#/%E6%94%B6%E8%97%8F/getUserCollectionsByUsername) 获得数据，在返回结果最后的 total 属性中可以看到你的记录总数，由于单次请求最多返回 50 条记录，如果超过 50 条需要修改 offset 分页参数多获取几次，最后将所有数据汇总保存为 JSON 文件。

### 导入数据

将 JSON 文件放到 mediaX 程序相同目录下，执行命令：

```bash
# Linux / macOS
./mediax --import <douban|bangumi> --file <file.json> [--download-image]
# Windows
mediax.exe --import <douban|bangumi> --file <file.json> [--download-image]

# e.g. 导入豆瓣数据
# ./mediax --import douban --file tofu[xxxxxx].json --download-image
```

最后的 `--download-image` 为可选参数，如果加上则导入的时候会尝试下载封面图片，如果数据量大的话会比较耗时（为了避免 IP 被 ban 下载间隔为 1s），请耐心等待。

不推荐重复导入一个文件，如果重复导入文件，目前只是简单的比对已导入的记录（原链接）和已下载的图片文件是否已经存在，如果存在则跳过导入。

### 导出数据

mediaX 支持导出内部数据为 JSON 文件，数据格式如下：

```
{
  "subjects": [
    {
      "uuid": string,
      "subject_type": string,
      "title": string,
      "alt_title": string,
      "pub_date": string,
      "creator": string,
      "press": string,
      "status": int,
      "rating": int,
      "summary": string,
      "comment": string,
      "external_url": string,
      "mark_date": string,
      "created_at": string
    }
  ],
  "export_time": string,
  "total_count": int
}
```

其中 status 表示条目标记状态 - 1: 想看, 2: 在看, 3: 已看, 4: 搁置, 5: 抛弃。导出命令：

```bash
# Linux / macOS
./mediax --export <all|anime|movie|book|tv|game> [--limit <number>]
# Windows
mediax.exe --export <all|anime|movie|book|tv|game> [--limit <number>]

# e.g. 导出最近 5 条图书数据，如果不加 --limit 参数则导出该类型全部记录
# ./mediax --export book --limit 5
```

导出的文件将保存在程序目录下。

### API

目前 mediaX 支持通过 API 获取基本的个人收藏条目数据，请求接口如下：

```
/api/v0/collection
```

返回格式：

```
{
  "subjects": [
    {
      "uuid": string,
      "subject_type": string,
      "title": string,
      "alt_title": string,
      "pub_date": string,
      "creator": string,
      "press": string,
      "status": int,
      "rating": int,
      "summary": string,
      "comment": string,
      "external_url": string,
      "mark_date": string,
      "created_at": string
    }
  ],
  "response_time": string,
  "total_count": int,
  "limit": int,
  "offset": int
}
```

你可以使用 `--api-key` 参数生成一个 API Key：
```bash
# Linux / macOS
./mediax --api-key
# Windows
mediax.ext --api-key

# 输出:
------- Generated API Key -------
API Key: 6ElNVkplRJgasQKfRyFNRDvxl0iV1kebIJpVl9Dt_Eg=
Hashed API Key: QEr6mA6HkILFwBYckw4Ek+9v41ooV64VGebOSDwqiKM=
---------------------------------
```

其中 Hashed API Key 需要复制到配置文件 `config.json` 的 `api_key` 字段中。请保管好 API Key，不要在非加密的公网中使用。如需重置，重新生成并替换即可。

可选参数：

- type: 获取数据的类型，默认为所有类型，可选 book, movie, tv, anime, game
- limit: 获取数据的数量限制，默认（最大）为 50
- offset: 获取数据的起始位置（跳过的记录数量），默认为 0
- sort: 排序方式，默认为 1（最近添加），可选 2: 最近标记，3: 最早添加，4: 最早标记

例如，使用 `curl` 命令获取数据：

```bash
# 获取最近 5 条图书数据
curl "http://localhost:8080/api/v0/collection?type=book&limit=5" \
  -H "Authorization: Bearer 6ElNVkplRJgasQKfRyFNRDvxl0iV1kebIJpVl9Dt_Eg="
# 获取第 6 至 10 条图书数据
curl "http://localhost:8080/api/v0/collection?type=book&limit=5&offset=5" \
  -H "Authorization: Bearer 6ElNVkplRJgasQKfRyFNRDvxl0iV1kebIJpVl9Dt_Eg="
```