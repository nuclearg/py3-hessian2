# hessian2 的 py3 实现

# 序列化
`hessian2.dumps(Any) -> bytes`

```
from hessian2 import dumps

dumps(1)
dumps('aaa')
dumps([1, 2, 3])
dumps({'a': 3, 'b': '4', c: [1, 2, 3]})
dumps({'#class': 'com.xxx.yyy.SomeDTO', 'fieldA': 'aaa', 'fiedlB': 'bbb'})
```

# 反序列化
`hessian2.loads(bytes) -> Any`
