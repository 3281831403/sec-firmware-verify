# sec-firmware-verify

## 题面

设备升级通道被刷进旧固件，回滚检测居然一路放行：清单缺少版本字段时被默认成零，旧固件可以冒充新版本；镜像哈希用内置哈希函数，结果不可复现且容易碰撞；签名比较用普通等号，不是恒定时间比较；签名比较先比长度再比内容，长度不同就提前返回，泄漏长度信息；哈希链只比较当前父哈希不递推，中间断裂检查不到；版本单调判断用严格小于，相同版本号可以重放；版本下限由调用方传入且不校验来源，传零等于关掉回滚保护；综合校验先验签后比哈希，哈希不一致也返回通过；清单校验不检查哈希长度，截断的哈希也能过；批量校验复用版本下限，后一批沿用了前一批的阈值。fw/verify.py 是核心，tests/test_verify.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

```powershell
cd D:\gsb-20261119\sec-firmware-verify
python -m pytest tests -q
```

初始状态应恰好为：

```text
15 failed
```

15 个失败必须全部来自测试调用 `fw/verify.py` 中 `raise NotImplementedError` 的桩函数；不允许出现 collection error、import error 或 syntax error，也不允许跳过测试。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 目录

```text
sec-firmware-verify/
  README.md
  conftest.py
  .gitignore
  fw/__init__.py
  fw/verify.py
  tests/test_verify.py
```

## 约束

- 只使用标准库（`hashlib`、`hmac`、`json`）与 pytest，离线运行，不使用随机数。
- `fw/verify.py` 的 8 个函数当前全部是桩；函数契约写在各函数 docstring 中，容差为 0：版本必须严格前进（同版本视为重放）、父哈希链必须逐级递推、签名必须常量时间比较、镜像哈希与签名必须同时通过。
- `tests/test_verify.py` 是不可修改的验收标准；不要改测试、加 skip/xfail、放宽断言或加 monkeypatch 来制造绿色，只实现 `fw/verify.py`。
- 不得联网，不得引入第三方依赖。
