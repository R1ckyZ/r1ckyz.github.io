# Introduction

记录自己的研究心得，涉及以下内容：

- WEB安全中的深度学习
- 样本对抗
- Java及其框架CVE研究和复现
- 内网渗透
- 文献阅读

**注：部分文章因渲染失败无法在线阅读，可到指定仓库查阅**

喜欢的师傅麻烦给我的小日记点个star⭐~

## How to build a GitBook?

安装nvm，找到nvm的安装路径

```
where nvm 或 which nvm
```

在settings.txt处添加国内源

```
node_mirror: https://npm.taobao.org/mirrors/node/
npm_mirror: https://npm.taobao.org/mirrors/npm/
```

再通过管理员下载对应的nodejs版本并启用

```
nvm install v10.23.0
nvm use v10.23.0
```

下载gitbook

```
npm install gitbook-cli -g
```

初始化gitbook

```
gitbook init
```

配置SUMMARY.md，书籍的目录结构在这里配置，最后建立gitbook

```
gitbook build
```

