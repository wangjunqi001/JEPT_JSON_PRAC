#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <float.h>
#include <math.h>
#include <errno.h>
#include <assert.h>
#include "leptjson_01.h"

#define json_set_null(v) json_free(v)
#ifndef JSON_PARSE_STACK_INIT_SIZE
#define JSON_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef JSON_PARSE_STRINGIFY_INIT_SIZE
#define JSON_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)
#define EXPECT(c,ch) do{assert(*c->json==ch);++(c->json);}while(0)
#define ISDIGIT(ch) ( (ch) >= '0'  && (ch) <= '9' )
#define ISDIGIT1to9(ch) ( (ch) >= '1'  && (ch) <= '9' )
#define PUT(c,ch) do{ *(char*)json_parse_push(c,sizeof(char)) = (ch); }while(0)
#define PUTS(c,s,len) do {memcpy(json_parse_push(c,len),s,len);}while(0)
typedef struct{
	const char* json;
	char* stack;
	size_t size,top;
}json_context;

static void* json_parse_push(json_context* c,size_t size){
	void* ret;
	assert(size > 0);
	if (c->top + size >= c->size){
		if (c->top + c->size == 0)
			c->size = JSON_PARSE_STACK_INIT_SIZE;
		while(c->top + size >= c->size)
			c->size += c->size >> 1;
		c->stack = (char*)realloc(c->stack,c->size);
	}
	ret = c->stack + c->top;
	c->top += size;
	return ret;
}

static void* json_parse_pop(json_context* c, size_t size){
	if (size == 0)
		return c->stack + c->top;
	assert(c->stack);
	return c->stack + (c->top -= size);
}

void json_free(json_value* v){
	size_t i;
	assert(v != NULL);
	switch (v->type){
		case JSON_STRING:free(v->u.s.s); 
					break;
		case JSON_ARRAY:
			for (i = 0; i < json_get_array_size(v); ++i)
				json_free(json_get_array_element(v, i));
			free(v->u.a.e);
			break;
		case JSON_OBJECT:
			for (i = 0; i < json_get_object_size(v); ++i){
				free(v->u.o.m[i].k);
				json_free(&v->u.o.m[i].v);
			}
			free(v->u.o.m);
			break;
		default: break;
	}
	v->type = JSON_NULL;
}

static void json_parse_whitespace(json_context* c){
	const char* p = c->json;
	while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r')
		++p;
	c->json = p;
}

void json_set_boolean(json_value* v, int b){
	assert(v != NULL);
	json_free(v);
	if (b != 0)
		v->type = JSON_TRUE;
	else
		v->type = JSON_FALSE;
}

static int json_parse_literal(json_context* c, json_value* v,const char * literal,json_type type){
	size_t i = 0;
	EXPECT(c,literal[0]);
	for (i = 0; literal[i + 1]; ++i){
		if (c->json[i] != literal[i + 1])
			return JSON_PARSE_INVALID_VALUE;
	}
	c->json += i;
	v->type = type;
	return JSON_PARSE_OK;
}

void json_set_string(json_value* v, const char * s, size_t len){
	assert(v != NULL && ( s!=NULL || len == 0));
	json_free(v);
	v->u.s.s = (char*)malloc(len + 1);
	memcpy(v->u.s.s,s,len);
	v->u.s.s[len] = '\0';
	v->u.s.len = len;
	v->type = JSON_STRING;
}
	
void json_set_number(json_value* v, double n){
	assert(v != NULL);
	json_free(v);
	v->u.n = n;
	v->type = JSON_NUMBER;
}

static int json_parse_number(json_context* c,json_value* v){
	const char *p = c->json;
	if (*p == '-') ++p;
	if (*p == '0') ++p;
	else{
		if (!ISDIGIT1to9(*p))
			return JSON_PARSE_INVALID_VALUE;
		for (p++; ISDIGIT(*p); p++);//  can't use !!!!!while(ISDIGIT(*p++))!!!! 
	}
	if (*p == '.'){
		++p;
		if (!ISDIGIT(*p))
			return JSON_PARSE_INVALID_VALUE;
		for (p++; ISDIGIT(*p);p++);
	}
	if (*p == 'e' || *p == 'E'){
		++p;
		if (*p == '+' || *p == '-') ++p;
		if (!ISDIGIT(*p))
			return JSON_PARSE_INVALID_VALUE;
		for (p++; ISDIGIT(*p); p++);
	}
	errno = 0;
	v->u.n = strtod(c->json,NULL);
	if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
		return JSON_PARSE_NUMBER_TOO_BIG;
	v->type = JSON_NUMBER;
	c->json = p;
	return JSON_PARSE_OK;
}

static const char* json_parse_hex4(const char* p,unsigned * u){
	int i = 3;
	int base = 0;
	while (i >= 0){
		if (ISDIGIT(*p)) base = *p - '0';
		else if (*p == 'a' || *p == 'A') base = 10;
		else if (*p == 'b' || *p == 'B') base = 11;
		else if (*p == 'c' || *p == 'C') base = 12;
		else if (*p == 'd' || *p == 'D') base = 13;
		else if (*p == 'e' || *p == 'E') base = 14;
		else if (*p == 'f' || *p == 'F') base = 15;
		else return NULL;
		(*u) |= base << 4 * i;
		++p;
		--i;
	}
	return p;
}

static void json_encode_utf8(json_context* c, const unsigned u){
	assert(u >= 0x00 && u <= 0x10ffff);
	if (u >= 0x00 && u <= 0x7f){
		PUT(c, (char)(u & 0x7f));
	}
	else if (u >= 0x80 & u <= 0x7ff){
		PUT(c, 0xc0| (u >> 6) & 0x1f);
		PUT(c, 0x80|  u       & 0x3f);
	}
	else if (u >= 0x800 && u <= 0xffff){
		PUT(c, 0xe0 | (u >> 12) & 0x0f);
		PUT(c, 0x80 | (u >> 6)  & 0x3f);
		PUT(c, 0x80 |  u        & 0x3f);
	}
	else if (u >= 0x10000 && u <= 0x10ffff){
		PUT(c, 0xf0 | (u >> 18) & 0x07);
		PUT(c, 0x80 | (u >> 12) & 0x3f);
		PUT(c, 0x80 | (u >> 6)  & 0x3f);
		PUT(c, 0x80 | u         & 0x3f);
	}
}

static int json_parse_string_raw(json_context* c, char** str, size_t* lenth){
	EXPECT(c, '\"');
	size_t head = c->top, len;
	const char* p = c->json;
	unsigned u = 0, u2 = 0;
	for (;;){
		char ch = *p++;
		switch (ch){
		case '\"':
			len = c->top - head;
			*str = (char*)malloc(len+1);
			memcpy(*str,(const char*)json_parse_pop(c, len), len);
			(*str)[len] = '\0';
			*lenth = len;
			c->json = p;
			return JSON_PARSE_OK;
		case '\0':
			STRING_ERROR(JSON_PARSE_MISS_QUOTATION_MARK);
		case '\\':
			switch (*p++){
			case 'n':PUT(c, (char)0x0A); break;
			case '"':PUT(c, (char)0x22); break;
			case '/':PUT(c, (char)0x2F); break;
			case 'b':PUT(c, (char)0x08); break;
			case 'f':PUT(c, (char)0x0C); break;
			case 'r':PUT(c, (char)0x0D); break;
			case 't':PUT(c, (char)0x09); break;
			case '\\':PUT(c, '\\'); break;
			case'u':if (!(p = json_parse_hex4(p, &u)))
				STRING_ERROR(JSON_PARSE_INVALID_UNICODE_HEX);
				if (u >= 0xd800 && u <= 0xdbff){
					if ((*p++) != '\\')
						STRING_ERROR(JSON_PARSE_INVALID_UNICODE_SURROGATE);
					if ((*p++) != 'u')
						STRING_ERROR(JSON_PARSE_INVALID_UNICODE_SURROGATE);
					if (!(p = json_parse_hex4(p, &u2)))
						STRING_ERROR(JSON_PARSE_INVALID_UNICODE_HEX);
					if (u2 < 0xdc00 || u2 > 0xffff)
						STRING_ERROR(JSON_PARSE_INVALID_UNICODE_SURROGATE);
					u = 0x10000 + (((u - 0xd800) << 10) & 0xffc0) + ((u2 - 0xdc00) & 0x03ff);
				}
				json_encode_utf8(c, u);
				break;
			default:
				STRING_ERROR(JSON_PARSE_INVALID_STRING_ESCAPE);
			}
			break;
		default:
			if ((unsigned char)ch < 0x20) {
				STRING_ERROR(JSON_PARSE_INVALID_STRING_CHAR);
			}
			PUT(c, ch);
		}
	}
}

static int json_parse_string(json_context* c, json_value* v){
	int ret;
	size_t len;
	char* str;
	if ((ret = json_parse_string_raw(c, &str, &len)) == JSON_PARSE_OK){
		v->u.s.s = str;
		v->u.s.len = len;
		v->type = JSON_STRING;
	}
	return ret;
}

static int json_parse_value(json_context* c, json_value* v);

static json_parse_array(json_context* c, json_value* v){
	size_t size = 0;
	int ret;
	int i = 0;
	EXPECT(c,'[');
	json_parse_whitespace(c);
	if (*c->json == ']'){
		c->json++;
		json_set_array(v, 0);
		return JSON_PARSE_OK;
	}
	for (;;){
		json_value e;
		json_init(&e);
		if (ret = json_parse_value(c, &e) != JSON_PARSE_OK)
			break;
		memcpy(json_parse_push(c,sizeof(json_value)),&e,sizeof(json_value));
		++size;
		json_parse_whitespace(c);
		if (*c->json == ','){
			++(c->json);
			json_parse_whitespace(c);
		}
		else if (*c->json == ']'){
			c->json++;
			json_set_array(v,size);
			v->u.a.size = size;
			size *= sizeof(json_value);
			memcpy(v->u.a.e = (json_value*)malloc(size), json_parse_pop(c, size), size);
			return JSON_PARSE_OK;
		}
		else{
			ret = JSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
			break;
		}
	}
	for (i = 0; i < size; ++i)
		json_free((json_value*)json_parse_pop(c, sizeof(json_value)));
	return ret;
}

static int json_parse_object(json_context* c, json_value* v){
	size_t size;
	json_member m;
	int ret;
	int i;
	EXPECT(c, '{');
	json_parse_whitespace(c);
	if (*c->json == '}'){
		c->json++;
		v->type = JSON_OBJECT;
		v->u.o.m = 0;
		v->u.o.size = 0;
		return JSON_PARSE_OK;
	}
	m.k = NULL;
	size = 0;
	for (;;){
		json_init(&m.v);
		json_parse_whitespace(c);
		if (*c->json != '"'){
			ret = JSON_PARSE_MISS_KEY;
			break;
		}
		if (ret = json_parse_string_raw(c, &m.k, &m.klen) != JSON_PARSE_OK)
			break;
		json_parse_whitespace(c);
		if (*c->json != ':'){
			ret = JSON_PARSE_MISS_COLON;
			break;
		}
		c->json++;
		json_parse_whitespace(c);
		if ((ret = json_parse_value(c, &m.v)) != JSON_PARSE_OK)
			break;
		memcpy(json_parse_push(c, sizeof(json_member)), &m, sizeof(json_member));
		size++;
		m.k = NULL; /**** !move ownership from m to stack! *****/
		json_parse_whitespace(c);
		if (*c->json == ',')
			c->json++;
		else if (*c->json == '}'){
			c->json++;
			v->type = JSON_OBJECT;
			v->u.o.size = size;
			size *= sizeof(json_member);
			memcpy(v->u.o.m = (json_member*)malloc(size), json_parse_pop(c, size), size); /**! move ownership from stack to v!**/ 
			return JSON_PARSE_OK;
		}else{
			ret = JSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
			break;
		}
	}
	free(m.k);
	for (i = 0; i < size; ++i){
		json_member* mem = (json_member*)json_parse_pop(c, sizeof(json_member));
		json_free(&mem->v);
		free(mem->k);
	}
	v->type = JSON_NULL;
	return ret;
}

static int json_parse_value(json_context* c, json_value* v){
	switch (*c->json){
	case 'n':return json_parse_literal(c,v,"null",JSON_NULL);
	case 't':return json_parse_literal(c, v, "true", JSON_TRUE);
	case 'f': return json_parse_literal(c, v, "false", JSON_FALSE);
	case '\"': return json_parse_string(c,v);
	case '[': return json_parse_array(c, v);
	case '{': return json_parse_object(c, v);
	default: return json_parse_number(c,v);
	case '\0': return JSON_PARSE_EXPECT_VALUE;
	}
}

int json_parse(json_value* v, const char* json){
	json_context c;

	assert(v != NULL);
	c.json = json;
	v->type = JSON_NULL;
	c.stack = NULL;
	c.size = c.top = 0;
	json_init(v);
	json_parse_whitespace(&c);
	int ret = json_parse_value(&c, v);
	if (ret == JSON_PARSE_OK){
		json_parse_whitespace(&c);
		if (c.json[0] != '\0'){
			v->type = JSON_NULL;
			return JSON_PARSE_ROOT_NOT_SINGULAR;
		}
	}
	assert(c.top == 0);
	if (c.stack!=NULL)
		free(c.stack);
	return ret;
}

static void json_stringify_string(json_context* c, const char* s,size_t len){
	static const char hex_digit[] = { '0','1', '2', '3', '4', '5', '6', '7', '8', '9', 'A','B', 'C', 'D', 'E', 'F' };
	size_t i,size;
	char *p, *head;
	assert(s != NULL);
	head = p = (char*)json_parse_push(c, size = len * 6 + 2);
	*p++ = '\"';
	for (i=0;i<len;++i){
		unsigned char ch = (unsigned char)s[i];//ÒÆÎ»²¹0
		switch (ch){
		case '\r': *p++ = '\\'; *p++ = 'r'; break;
		case '\t': *p++ = '\\'; *p++ = 't'; break;
		case '\n': *p++ = '\\'; *p++ = 'n'; break;
		case '\b': *p++ = '\\'; *p++ = 'b'; break;
		case '\f': *p++ = '\\'; *p++ = 'f'; break;
		case '\\': *p++ = '\\'; *p++ = '\\'; break;
		case '\"': *p++ = '\\'; *p++ = '\"'; break;
		default:
			if (ch < 0x20){
				*p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
				*p++ = hex_digit[ch >> 4]; //ch >> 4 & 15
				*p++ = hex_digit[ch & 15];
			}
			else
				*p++ = s[i];
		}
	}
	*p++ = '\"';
	c->top -= size - (p - head);
}

static void json_stringify_value(json_context* c, json_value* v){
	size_t i;
	switch (v->type){
	case JSON_TRUE: PUTS(c, "true", 4); break;
	case JSON_FALSE:PUTS(c, "false", 5); break;
	case JSON_NULL:PUTS(c, "null", 4); break;
	case JSON_NUMBER:
		c->top -= (32 - sprintf((char*)json_parse_push(c, 32), "%.17g", v->u.n));
		break;
	case JSON_STRING:json_stringify_string(c,v->u.s.s,v->u.s.len); break;
	case JSON_ARRAY:
		PUT(c, '[');
		for (i = 0; i < v->u.a.size; ++i){
			if (i>0)
				PUT(c,',');
			json_stringify_value(c,&v->u.a.e[i]);
		}
		PUT(c, ']');
		break;
	case JSON_OBJECT:
		PUT(c, '{');
		for (i = 0; i < v->u.o.size; ++i){
			if (i>0)
				PUT(c, ',');
			json_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
			PUT(c,':');
			json_stringify_value(c, &v->u.o.m[i].v);
		}
		PUT(c, '}');
		break;
	default: assert(0 && "invalid value");
	}
}

char* json_stringify(json_value* v,size_t* length){
	json_context c;
	assert(v != NULL);
	c.stack = (char*)malloc(c.size = JSON_PARSE_STRINGIFY_INIT_SIZE);
	c.top = 0;
	json_stringify_value(&c, v);
	if(length)
		*length = c.top;
	PUT(&c, '\0');
	return c.stack;
}

json_type json_get_type(const json_value* v){
	assert(v != NULL);
	return v->type;
}

double json_get_number(const json_value* v){
	assert(v!=NULL && v->type==JSON_NUMBER);
	return v->u.n;
}

const char* json_get_string(const json_value* v){
	assert(v != NULL && v->type == JSON_STRING);
	return v->u.s.s;
}

size_t json_get_string_lenth(const json_value* v){
	assert(v != NULL && v->type == JSON_STRING);
	return v->u.s.len;
}

size_t json_get_boolean(const json_value* v){
	assert(v != NULL && (v->type == JSON_FALSE || v->type == JSON_TRUE));
	if (v->type == JSON_TRUE)
		return 1;
	else
		return 0;
}

size_t json_get_array_size(const json_value* v){
	assert(v != NULL && v->type == JSON_ARRAY);
	return v->u.a.size;
}

size_t json_get_array_capacity(const json_value* v){
	assert(v != NULL && v->type == JSON_ARRAY);
	return v->u.a.capacity;
}

void json_reserve_array(json_value* v,size_t capacity){
	assert(v!= NULL &&v->type == JSON_ARRAY);
	if (capacity > v->u.a.capacity){
		v->u.a.capacity = capacity;
		v->u.a.e = (json_value*)realloc(v->u.a.e, capacity * sizeof(json_value));
	}
}

void json_shrink_array(json_value* v){
	assert(v != NULL &&v->type == JSON_ARRAY);
	if (v->u.a.capacity > v->u.a.size){
		v->u.a.capacity = v->u.a.size;
		v->u.a.e = (json_value*)realloc(v->u.a.e,v->u.a.size * sizeof(json_value));
	}
}

json_value* json_pushback_array_element(json_value* v){
	assert(v != NULL && v->type == JSON_ARRAY);
	if (v->u.a.size == v->u.a.capacity)
		json_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
	json_init(&v->u.a.e[v->u.a.size]);
	return &v->u.a.e[v->u.a.size++];
}

void json_popback_array_element(json_value* v){
	assert(v != NULL && v->type == JSON_ARRAY && v->u.a.size > 0);
	json_free(&v->u.a.e[--v->u.a.size]);
}

json_value* json_insert_array_element(json_value* v, size_t index){
	assert(v != NULL && v->type == JSON_ARRAY);
	if (v->u.a.size == v->u.a.capacity)
		json_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
	if (index >= v->u.a.size){
		json_init(&v->u.a.e[v->u.a.size]);
		return &v->u.a.e[v->u.a.size++];
	}
	else{ 
		size_t i;
		for (i = v->u.a.size; i > index; --i)
			json_move(&v->u.a.e[i], &v->u.a.e[i - 1]);
		v->u.a.size++;
		return &v->u.a.e[index];
	}
}

void json_clear_array(json_value* v){
	assert(v != NULL && v->type == JSON_ARRAY);
	size_t i;
	for (i = 0; i < v->u.a.size; ++i)
		json_free(&v->u.a.e[i]);
	v->u.a.size = 0;
}

void json_erase_array_element(json_value* v, size_t index, size_t count){
	assert(v != NULL && v->type == JSON_ARRAY);
	size_t i;
	if (index >= v->u.a.size)
		return;
	else if (index + count >= v->u.a.size){
		for (i = index; i < v->u.a.size; ++i)
			json_free(&v->u.a.e[i]);
		v->u.a.size = index;
	}
	else if(count > 0){
		for (i = index + count ; i < v->u.a.size; ++i)
			json_move(&v->u.a.e[i-count],&v->u.a.e[i]);
		v->u.a.size -= count;
	}
}

json_value* json_get_array_element(const json_value* v,size_t index){
	assert(v != NULL && v->type == JSON_ARRAY);
	assert(index < v->u.a.size);
	return &v->u.a.e[index];
}

size_t json_get_object_size(const json_value* v){
	assert(v != NULL && v->type == JSON_OBJECT);
	return v->u.o.size;
}

size_t json_get_object_capacity(const json_value* v){
	assert(v != NULL && v->type == JSON_OBJECT);
	return v->u.o.capacity;
}

const char* json_get_object_key(const json_value* v, size_t index){
	assert(v != NULL && v->type == JSON_OBJECT);
	assert(index < v->u.o.size);
	return v->u.o.m[index].k;
}
size_t json_get_object_key_lenth(const json_value* v, size_t index){
	assert(v != NULL && v->type == JSON_OBJECT);
	assert(index < v->u.o.size);
	return v->u.o.m[index].klen;
}

json_value* json_get_object_value(const json_value* v, size_t index){
	assert(v != NULL && v->type == JSON_OBJECT);
	assert(index < v->u.o.size);
	return &v->u.o.m[index].v;
}

size_t json_find_object_index(const json_value* v, const char* key,size_t klen){
	assert(v != NULL && v->type == JSON_OBJECT &&key != NULL);
	int i;
	for (i = 0; i < v->u.o.size; ++i)
	if (v->u.o.m[i].klen == klen && strcmp(v->u.o.m[i].k, key) == 0)
		return i;
	return JSON_KEY_NOT_EXIST;
}

json_value* json_find_object_value(const json_value* v, const char* key, size_t klen){
	assert(v != NULL && v->type == JSON_OBJECT &&key != NULL);
	size_t index = json_find_object_index(v, key, klen);
	return index != JSON_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

void json_set_object(json_value* v,size_t capacity){
	assert(v != NULL);
	json_free(v);
	v->type = JSON_OBJECT;
	v->u.o.capacity = capacity;
	v->u.o.size = 0;
	v->u.o.m = capacity > 0 ? (json_member*)malloc(sizeof(json_member) * capacity) : NULL;
}

void json_reserve_object(json_value* v, size_t capacity){
	assert(v != NULL && v->type == JSON_OBJECT);
	if (capacity > v->u.o.capacity){
		v->u.o.capacity = capacity;
		v->u.o.m = (json_member*)realloc(v->u.o.m,sizeof(json_member) * capacity);
	}
}

void json_shrink_object(json_value* v){
	assert(v != NULL && v->type == JSON_OBJECT);
	if (v->u.o.capacity > v->u.o.size){
		v->u.o.capacity = v->u.o.size;
		v->u.o.m = (json_member*)realloc(v->u.o.m,sizeof(json_member) * v->u.o.size);
	}
}

void json_clear_object(json_value* v){
	assert(v != NULL && v->type == JSON_OBJECT);
	size_t i;
	for (i = 0; i < v->u.o.size; ++i){
		free(v->u.o.m[i].k);
		json_free(&v->u.o.m[i].v);
	}
	v->u.o.size = 0;
}

json_value* json_set_object_value(json_value* v, const char* key, size_t klen){
	assert(v != NULL && v->type == JSON_OBJECT);
	int index;
	if (index = json_find_object_index(v, key, klen) != JSON_KEY_NOT_EXIST)
		return &v->u.o.m[index].v;
	else{
		if (v->u.o.capacity == v->u.o.size)
			json_reserve_object(v,v->u.o.capacity == 0 ? 1:v->u.o.capacity * 2);
		v->u.o.m[v->u.o.size].klen = klen;
		v->u.o.m[v->u.o.size].k = (char*)malloc( klen + 1 );
		memcpy(v->u.o.m[v->u.o.size].k, key, klen + 1);
		json_init(&v->u.o.m[v->u.o.size].v);
		return &v->u.o.m[v->u.o.size++].v;
	}
}

void json_remove_object_value(json_value* v, size_t index){
	assert(v != NULL && v->type == JSON_OBJECT);
	if (index < v->u.o.size ){
		if (index < v->u.o.size - 1){
			size_t i;
			for (i = index; i < v->u.o.size - 1; ++i){
				v->u.o.m[i].k = (char*)malloc(v->u.o.m[i+1].klen + 1);
				memcpy(v->u.o.m[i].k, v->u.o.m[i + 1].k, v->u.o.m[i + 1].klen + 1);
				v->u.o.m[i].klen = v->u.o.m[i + 1].klen;
				json_move(&v->u.o.m[i].v, &v->u.o.m[i + 1].v);
			}
		}
		free(v->u.o.m[v->u.o.size-1].k);
		json_free(&v->u.o.m[--v->u.o.size].v);
	}
}

int json_is_equal(const json_value* lhs, const json_value* rhs){
	assert(lhs != NULL&&rhs != NULL);
	size_t i,index;
	if (lhs->type != rhs->type)
		return 0;
	switch (lhs->type){
		case JSON_NUMBER:
			return lhs->u.n == rhs->u.n;
		case JSON_STRING:
			return lhs->u.s.len == rhs->u.s.len &&
				strcmp(lhs->u.s.s, rhs->u.s.s) == 0;
		case JSON_ARRAY:
			if (lhs->u.a.size != rhs->u.a.size)
				return 0;
			for (i=0;i<lhs->u.a.size;++i)
				if (json_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i]) == 0)
					return 0;
			return 1;
		case JSON_OBJECT:
			if (lhs->u.o.size != rhs->u.o.size)
				return 0;
			for (i = 0; i < lhs->u.o.size;++i)
				if (index = json_find_object_index(rhs, lhs->u.o.m[i].k, lhs->u.o.m[i].klen) == JSON_KEY_NOT_EXIST)
					return 0;
				else if (json_is_equal(&lhs->u.o.m[i].v, json_find_object_value(rhs, lhs->u.o.m[i].k, lhs->u.o.m[i].klen)) == 0)
					return 0;
			return 1;
		default:
			return 1;
	}
}

void json_set_array(json_value* v, size_t capcity){
	assert(v != NULL);
	json_free(v);
	v->type = JSON_ARRAY;
	v->u.a.size = 0;
	v->u.a.capacity = capcity;
	v->u.a.e = capcity > 0 ? (json_value*)malloc(sizeof(json_value)* capcity) : NULL;
}

void json_copy(json_value* dst,const json_value* src){
	size_t i;
	assert(dst!= NULL && src != NULL && dst != src);
	json_free(dst);
	switch (src->type){
		case JSON_STRING:
			json_set_string(dst, src->u.s.s, src->u.s.len); 
			break;
		case JSON_ARRAY:
			dst->u.a.size = dst->u.a.capacity = src->u.a.size;
			dst->u.a.e = (json_value*)malloc(sizeof(json_value)* src->u.a.size);
			for (i = 0; i < src->u.a.size; ++i){
				json_copy(&dst->u.a.e[i], &src->u.a.e[i]);
			}
			dst->type = src->type;
			break;
		case JSON_OBJECT:
			dst->u.o.size = dst->u.o.capacity = src->u.o.size;
			dst->u.o.m = (json_member*)malloc(sizeof(json_member)* src->u.o.size);
			for (i = 0; i < src->u.o.size; ++i){
				dst->u.o.m[i].klen = src->u.o.m[i].klen;
				dst->u.o.m[i].k = (char*)malloc(src->u.o.m[i].klen + 1);
				memcpy(dst->u.o.m[i].k, src->u.o.m[i].k, src->u.o.m[i].klen + 1);
				json_copy(&dst->u.o.m[i].v,&src->u.o.m[i].v);
				dst->type = src->type;
			}
			break;
		default:
			json_free(dst);
			memcpy(dst,src,sizeof(json_value));
			break;
	}
}

void json_move(json_value* dst, json_value* src){
	assert(dst != NULL && src != NULL && dst != src);
	json_free(dst);
	memcpy(dst,src,sizeof(json_value));
	json_init(src);
}

void json_swap(json_value* dst, json_value* src){
	assert(dst != NULL && src != NULL);
	if (dst != src){
		json_value temp;
		memcpy(&temp,src,   sizeof(json_value));
		memcpy(src,  dst,   sizeof(json_value));
		memcpy(dst,  &temp, sizeof(json_value));
	}
}
