# god_param
god_param

开发原因：
日常做渗透测试时，参数提取至关重要，一个好的参数表，可以拿来结合批量fuzz更多想不到的功能点，且更加好的联动god_link插件
但是找了一圈，找到的参数提取的，就唯有burp-sensitive-param-extractor的参数提取的还能用，但是他限定了只抓取proxy抓到的参数，且对该参数文件也没进行去重功能，且也不会删除匹配到的参数文件。
为了满足自己的需要就直接二开了，直接改的功能，大致的UI就没咋改。




增加功能：

①修改toolFlag，使其能够自动获取到所有的burp拓展的参数。

②增加IExtensionStateListener，实现每次重启burp时，自动删除参数的作用。

③增加返回包参数匹配，对返回包的内容进行参数匹配，调用了两次匹配，匹配出参数值。

④对参数写入文件时，进行去重判断，防止参数重复。

⑤更改部分ui界面。

⑥增加JTextArea和read功能，实现直接读取参数到列表中，便于直接在burp中进行测试。




修改功能：

①删除原作者的正则限定这些规则。

使用方法：

访问一个网站后，进行输入参数这些后，进行填入参数或者访问后。

![image](https://github.com/goddemondemongod/god_param/blob/main/image.png)


点击read按钮即可将相关的参数文件直接读取到列表
