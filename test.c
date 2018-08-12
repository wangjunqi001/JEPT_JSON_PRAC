#define _CRT_SECURE_NO_WARNINGS
#define _WINDOWS
#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#pragma warning(disable:4996)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <math.h>
#include <errno.h>
#include <float.h>
#include "leptjson_01.h"

static main_ret = 0;
static test_count = 0;
static test_pass = 0;


#define EXPECT_EQ_BASE(equality,expect,actual,format)\
do{\
	++test_count; \
if (equality)\
	test_pass++; \
	else{\
	fprintf(stderr, "%s:%d:expect: "format" actual "format"\n", __FILE__, __LINE__, expect, actual); \
	main_ret = 1; \
}\
} while (0)


#define EXPECT_EQ_TRUE(actual) EXPECT_EQ_BASE((actual)!=0,"true",actual,"%s")
#define EXPECT_EQ_FALSE(actual) EXPECT_EQ_BASE((actual)==0,"false",actual,"%s")
#define EXPECT_EQ_INT(expect,actual) EXPECT_EQ_BASE((expect)==(actual),expect,actual,"%d")
#define EXPECT_EQ_DOUBLE(expect,actual) EXPECT_EQ_BASE( (expect)==(actual),expect,actual,"%.17g")
#define EXPECT_EQ_STRING(expect,actual,len) EXPECT_EQ_BASE(( strcmp((expect),(actual))==0 && len == sizeof(expect)-1 ),expect,actual,"%s" )

#if defined(_MSC_VER)
#define EXPECT_EQ_SIZE_T(expect,actual) EXPECT_EQ_BASE((expect)==(actual),(size_t)(expect),(size_t)(actual),"%Iu")
#else
#define EXPECT_EQ_SIZE_T(expect,actual) EXPECT_EQ_BASE((expect)==(actual),(size_t)(expect),(size_t)(actual),"%zu")
#endif

#define TEST_ERROR(error,json) \
do{\
	json_value v; \
	v.type = JSON_FALSE; \
	EXPECT_EQ_INT(error, json_parse(&v, json)); \
	EXPECT_EQ_INT(JSON_NULL, json_get_type(&v)); \
	json_free(&v); \
} while (0)

static void test_parse_null(){
	json_value v;
	v.type = JSON_TRUE;
	EXPECT_EQ_INT(JSON_PARSE_OK,json_parse( &v,"null"));
	EXPECT_EQ_INT(JSON_NULL, json_get_type(&v));
}

static void test_parse_true(){
	json_value v;
	v.type = JSON_TRUE;
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, "true"));
	EXPECT_EQ_INT(JSON_TRUE, json_get_type(&v));
}

static void test_access_string(){
	json_value v;
	json_init(&v);
	json_set_string(&v,"",0);
	EXPECT_EQ_STRING("",json_get_string(&v),json_get_string_lenth(&v));
	json_set_string(&v, "Hello", 5);
	EXPECT_EQ_STRING("Hello", json_get_string(&v), json_get_string_lenth(&v));
	json_free(&v);
}

static void test_access_boolean(){
	json_value v;
	json_init(&v);
	json_set_string(&v, "a", 1);
	json_set_boolean(&v,0);
	EXPECT_EQ_FALSE(json_get_boolean(&v));
	json_set_boolean(&v, 1);
	EXPECT_EQ_TRUE(json_get_boolean(&v));
	json_free(&v);
}

static void test_access_number() {
	json_value v;
	json_init(&v);
	json_set_string(&v, "a", 1);
	json_set_number(&v, 1234.5);
	EXPECT_EQ_DOUBLE(1234.5, json_get_number(&v));
	json_free(&v);
}

#define TEST_NUMBER(expect,json) \
do{\
	json_value v; \
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, json)); \
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(&v)); \
	EXPECT_EQ_DOUBLE(expect, json_get_number(&v)); \
} while (0)

static void test_parse_false(){
	json_value v;
	v.type = JSON_TRUE;
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, "false"));
	EXPECT_EQ_INT(JSON_FALSE, json_get_type(&v));
}

#define TEST_STRING(expect,json)\
do{\
	json_value v; \
	json_init(&v); \
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, json)); \
	EXPECT_EQ_INT(JSON_STRING, json_get_type(&v)); \
	EXPECT_EQ_STRING(expect,json_get_string(&v),json_get_string_lenth(&v));\
} while (0)\

static void test_parse_root_not_sigular(){
	TEST_ERROR(JSON_PARSE_ROOT_NOT_SINGULAR, "0x0");
	TEST_ERROR(JSON_PARSE_ROOT_NOT_SINGULAR, "0x123");
	TEST_ERROR(JSON_PARSE_ROOT_NOT_SINGULAR,"0123");
}

static void test_parse_number(){
	TEST_NUMBER(0.0,"0");
	TEST_NUMBER(0.0, "-0");
	TEST_NUMBER(0.0, "-0.0");
	TEST_NUMBER(1.0, "1");
	TEST_NUMBER(1.234E+10,"1.234E+10");
	TEST_NUMBER(3.1416,"3.1416");
	TEST_NUMBER(-1.5,"-1.5");
	TEST_NUMBER(1e10,"1e10" );
	TEST_NUMBER(1E10, "1E10");
	TEST_NUMBER(1E+10,"1E+10");
	TEST_NUMBER(1E-10,"1E-10");
	TEST_NUMBER(-1E10,"-1E10");
	TEST_NUMBER(-1e10,"-1e10");
	TEST_NUMBER(-1E+10,"-1E+10");
	TEST_NUMBER(1.234E+10,"1.234E+10");
	TEST_NUMBER(1.234E-10,"1.234E-10");
	TEST_NUMBER(0.0,"1e-10000");
	TEST_NUMBER(1.79E308,"1.79E308");
	TEST_NUMBER(DBL_EPSILON,"  2.2204460492503131e-016 ");
	TEST_NUMBER(DBL_MAX,"1.7976931348623158e+308");
}

static void test_parse_invalid_value(){
	TEST_ERROR(JSON_PARSE_INVALID_VALUE,"+0");
	TEST_ERROR(JSON_PARSE_INVALID_VALUE,"+1");
	TEST_ERROR(JSON_PARSE_INVALID_VALUE, ".123");
	TEST_ERROR(JSON_PARSE_INVALID_VALUE, "123.");
	TEST_ERROR(JSON_PARSE_INVALID_VALUE, "INF");
	TEST_ERROR(JSON_PARSE_INVALID_VALUE, "inf");
	TEST_ERROR(JSON_PARSE_INVALID_VALUE, "NAN");
	TEST_ERROR(JSON_PARSE_INVALID_VALUE, "nan");
}

static void test_parse_number_too_big(){
	TEST_ERROR(JSON_PARSE_NUMBER_TOO_BIG, "1E309");
	TEST_ERROR(JSON_PARSE_NUMBER_TOO_BIG, "-1E309");
}

static void test_parse_string(){
	TEST_STRING("", "\"\"");
	TEST_STRING("Hello", "\"Hello\"");
	TEST_STRING("Hello\nWorld", "\"Hello\\nWorld\"");
	TEST_STRING("\" \\ / \b \f \n \r \t", "\"\\\" \\\\ \\/ \\b \\f \\n \\r \\t\"");
	TEST_STRING("Hello\0World", "\"Hello\\u0000World\"");
	TEST_STRING("\x24", "\"\\u0024\"");         /* Dollar sign U+0024 */
	TEST_STRING("\xC2\xA2", "\"\\u00A2\"");     /* Cents sign U+00A2 */
	TEST_STRING("\xE2\x82\xAC", "\"\\u20AC\""); /* Euro sign U+20AC */
	TEST_STRING("\xF0\x9D\x84\x9E", "\"\\uD834\\uDD1E\"");  /* G clef sign U+1D11E */
	TEST_STRING("\xF0\x9D\x84\x9E", "\"\\ud834\\udd1e\"");  /* G clef sign U+1D11E */
}

static void test_parse_invalid_string_escape() {
	TEST_ERROR(JSON_PARSE_INVALID_STRING_ESCAPE, "\"\\v\"");
	TEST_ERROR(JSON_PARSE_INVALID_STRING_ESCAPE, "\"\\'\"");
	TEST_ERROR(JSON_PARSE_INVALID_STRING_ESCAPE, "\"\\0\"");
	TEST_ERROR(JSON_PARSE_INVALID_STRING_ESCAPE, "\"\\x12\"");
}

static void test_parse_invalid_string_char() {
	TEST_ERROR(JSON_PARSE_INVALID_STRING_CHAR, "\"\x01\"");
	TEST_ERROR(JSON_PARSE_INVALID_STRING_CHAR, "\"\x1F\"");
}

static void test_parse_missing_quotation_mark() {
	TEST_ERROR(JSON_PARSE_MISS_QUOTATION_MARK, "\"");
	TEST_ERROR(JSON_PARSE_MISS_QUOTATION_MARK, "\"abc");
}

static void test_parse_invalid_unicode_hex() {
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u0\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u01\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u012\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u/000\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\uG000\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u0/00\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u0G00\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u0/00\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u00G0\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u000/\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_HEX, "\"\\u000G\"");
}

static void test_parse_invalid_unicode_surrogate() {
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uDBFF\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\\\\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\uDBFF\"");
	TEST_ERROR(JSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\uE000\"");
}

static void test_parse_array(){
	json_value v;
	json_init(&v);
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, "[null, false, true, 123, \"abc\"]"));
	EXPECT_EQ_INT(JSON_ARRAY, json_get_type(&v));
	EXPECT_EQ_INT(5, json_get_array_size(&v));
	EXPECT_EQ_INT(JSON_NULL, json_get_type(json_get_array_element(&v, 0)));
	EXPECT_EQ_INT(JSON_FALSE, json_get_type(json_get_array_element(&v, 1)));
	EXPECT_EQ_INT(JSON_TRUE, json_get_type(json_get_array_element(&v, 2)));
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(json_get_array_element(&v, 3)));
	EXPECT_EQ_INT(123, json_get_number(json_get_array_element(&v,3)));
	EXPECT_EQ_INT(JSON_STRING, json_get_type(json_get_array_element(&v, 4)));
	EXPECT_EQ_STRING("abc", json_get_string(json_get_array_element(&v, 4)),json_get_string_lenth(json_get_array_element(&v, 4)));
	json_free(&v);
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, "[[ ] , [ 0 ] , [ 0 , 1 ] , [ 0 , 1 , 2 ] ]"));
	EXPECT_EQ_INT(JSON_ARRAY, json_get_type(&v));
	EXPECT_EQ_INT(4, json_get_array_size(&v));

	EXPECT_EQ_INT(JSON_ARRAY, json_get_type(json_get_array_element(&v, 0)));
	EXPECT_EQ_INT(0, json_get_array_size(json_get_array_element(&v, 0)));

	EXPECT_EQ_INT(JSON_ARRAY, json_get_type(json_get_array_element(&v, 1)));
	EXPECT_EQ_INT(1, json_get_array_size(json_get_array_element(&v, 1)));
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(json_get_array_element(json_get_array_element(&v, 1),0)));
	EXPECT_EQ_INT(0, json_get_number(json_get_array_element(json_get_array_element(&v, 1), 0)));

	EXPECT_EQ_INT(JSON_ARRAY, json_get_type(json_get_array_element(&v, 2)));
	EXPECT_EQ_INT(2, json_get_array_size(json_get_array_element(&v, 2)));
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(json_get_array_element(json_get_array_element(&v, 2), 0)));
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(json_get_array_element(json_get_array_element(&v, 2), 1)));
	EXPECT_EQ_INT(0, json_get_number(json_get_array_element(json_get_array_element(&v, 2), 0)));
	EXPECT_EQ_INT(1, json_get_number(json_get_array_element(json_get_array_element(&v, 2), 1)));

	EXPECT_EQ_INT(JSON_ARRAY, json_get_type(json_get_array_element(&v, 3)));
	EXPECT_EQ_INT(3, json_get_array_size(json_get_array_element(&v, 3)));
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(json_get_array_element(json_get_array_element(&v, 3), 0)));
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(json_get_array_element(json_get_array_element(&v, 3), 1)));
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(json_get_array_element(json_get_array_element(&v, 3), 2)));
	EXPECT_EQ_INT(0, json_get_number(json_get_array_element(json_get_array_element(&v, 3), 0)));
	EXPECT_EQ_INT(1, json_get_number(json_get_array_element(json_get_array_element(&v, 3), 1)));
	EXPECT_EQ_INT(2, json_get_number(json_get_array_element(json_get_array_element(&v, 3), 2)));
	json_free(&v);
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, "[ ]"));
	EXPECT_EQ_INT(JSON_ARRAY, json_get_type(&v));
	EXPECT_EQ_INT(0, json_get_array_size(&v));
	json_free(&v);
}

static void test_parse_miss_comma_or_square_bracket() {
	TEST_ERROR(JSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1");
	TEST_ERROR(JSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1}");
	TEST_ERROR(JSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1 2");
	TEST_ERROR(JSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[[]");
}

static void test_parse_object(){
	json_value v;
	size_t i;

	json_init(&v);
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, " { } "));
	EXPECT_EQ_INT(JSON_OBJECT, json_get_type(&v));
	EXPECT_EQ_INT(0, json_get_object_size(&v));
	json_free(&v);

	json_init(&v);
	EXPECT_EQ_INT(JSON_PARSE_OK,json_parse(&v,
		"{"
		"\"n\" : null , "
		"\"f\" : false , "
		"\"t\" : true , "
		"\"i\" : 123 , "
		"\"s\" : \"abc\" , "
		"\"a\" : [ 1 , 2 , 3 ],"
		"\"o\" : { \"1\" : 1, \"2\" : 2, \"3\" : 3 }"
		" } "
		));
	EXPECT_EQ_INT(JSON_OBJECT, json_get_type(&v));
	EXPECT_EQ_SIZE_T(7, json_get_object_size(&v));
	EXPECT_EQ_STRING("n",json_get_object_key(&v,0),json_get_object_key_lenth(&v,0));
	EXPECT_EQ_INT(JSON_NULL, json_get_type(json_get_object_value(&v, 0)));
	EXPECT_EQ_STRING("f", json_get_object_key(&v, 1), json_get_object_key_lenth(&v, 1));
	EXPECT_EQ_INT(JSON_FALSE, json_get_type(json_get_object_value(&v, 1)));
	EXPECT_EQ_STRING("t", json_get_object_key(&v, 2), json_get_object_key_lenth(&v, 2));
	EXPECT_EQ_INT(JSON_TRUE, json_get_type(json_get_object_value(&v, 2)));
	EXPECT_EQ_STRING("i", json_get_object_key(&v, 3), json_get_object_key_lenth(&v, 3));
	EXPECT_EQ_INT(JSON_NUMBER, json_get_type(json_get_object_value(&v, 3)));
	EXPECT_EQ_DOUBLE(123.0, json_get_number(json_get_object_value(&v, 3)));
	EXPECT_EQ_STRING("s", json_get_object_key(&v, 4), json_get_object_key_lenth(&v, 4));
	EXPECT_EQ_INT(JSON_STRING, json_get_type(json_get_object_value(&v, 4)));
	EXPECT_EQ_STRING("abc", json_get_string(json_get_object_value(&v, 4)), json_get_string_lenth(json_get_object_value(&v, 4)));
	EXPECT_EQ_STRING("a", json_get_object_key(&v, 5), json_get_object_key_lenth(&v, 5));
	EXPECT_EQ_INT(JSON_ARRAY, json_get_type(json_get_object_value(&v, 5)));
	EXPECT_EQ_SIZE_T(3, json_get_array_size(json_get_object_value(&v, 5)));
	for (i = 0; i < 3; ++i){
		json_value* e = json_get_array_element(json_get_object_value(&v, 5), i);
		EXPECT_EQ_INT(JSON_NUMBER, json_get_type(e));
		EXPECT_EQ_DOUBLE(i + 1.0, json_get_number(e));
	}
	EXPECT_EQ_STRING("o", json_get_object_key(&v, 6), json_get_object_key_lenth(&v, 6));
	{
		json_value* o = json_get_object_value(&v, 6);
		EXPECT_EQ_INT(JSON_OBJECT, json_get_type(o));
		for (i = 0; i < 3; i++) {
			json_value* ov = json_get_object_value(o, i);
			EXPECT_EQ_SIZE_T(1,json_get_object_key_lenth(o, i));
			EXPECT_EQ_INT(JSON_NUMBER, json_get_type(ov));
			EXPECT_EQ_DOUBLE(i + 1.0, json_get_number(ov));
		}
	}
	json_free(&v);
}

static void test_parse_miss_key() {
	TEST_ERROR(JSON_PARSE_MISS_KEY, "{:1,");
	TEST_ERROR(JSON_PARSE_MISS_KEY, "{1:1,");
	TEST_ERROR(JSON_PARSE_MISS_KEY, "{true:1,");
	TEST_ERROR(JSON_PARSE_MISS_KEY, "{false:1,");
	TEST_ERROR(JSON_PARSE_MISS_KEY, "{null:1,");
	TEST_ERROR(JSON_PARSE_MISS_KEY, "{[]:1,");
	TEST_ERROR(JSON_PARSE_MISS_KEY, "{{}:1,");
	TEST_ERROR(JSON_PARSE_MISS_KEY, "{\"a\":1,");
}

static void test_parse_miss_colon() {
	TEST_ERROR(JSON_PARSE_MISS_COLON, "{\"a\"}");
	TEST_ERROR(JSON_PARSE_MISS_COLON, "{\"a\",\"b\"}");
}

static void test_parse_miss_comma_or_curly_bracket() {
	TEST_ERROR(JSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1");
	TEST_ERROR(JSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1]");
	TEST_ERROR(JSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1 \"b\"");
	TEST_ERROR(JSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":{}");
}

#define TEST_ROUNDTRIP(json)\
do {\
	json_value v; \
	char* json2; \
	size_t length; \
	json_init(&v); \
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v, json)); \
	json2 = json_stringify(&v, &length); \
	EXPECT_EQ_STRING(json, json2, length); \
	json_free(&v); \
	free(json2); \
} while (0)

static void test_stringify_number() {
	TEST_ROUNDTRIP("0");
	TEST_ROUNDTRIP("-0");
	TEST_ROUNDTRIP("1");
	TEST_ROUNDTRIP("-1");
	TEST_ROUNDTRIP("1.5");
	TEST_ROUNDTRIP("-1.5");
	TEST_ROUNDTRIP("3.25");
	TEST_ROUNDTRIP("1e+020");
	TEST_ROUNDTRIP("1.234e+020");
	TEST_ROUNDTRIP("1.234e-020");

	TEST_ROUNDTRIP("1.0000000000000002"); /* the smallest number > 1 */
	TEST_ROUNDTRIP("4.9406564584124654e-324"); /* minimum denormal */
	TEST_ROUNDTRIP("-4.9406564584124654e-324");
	TEST_ROUNDTRIP("2.2250738585072009e-308");  /* Max subnormal double */
	TEST_ROUNDTRIP("-2.2250738585072009e-308");
	TEST_ROUNDTRIP("2.2250738585072014e-308");  /* Min normal positive double */
	TEST_ROUNDTRIP("-2.2250738585072014e-308");
	TEST_ROUNDTRIP("1.7976931348623157e+308");  /* Max double */
	TEST_ROUNDTRIP("-1.7976931348623157e+308");
}

static void test_stringify_string() {
	TEST_ROUNDTRIP("\"\"");
	TEST_ROUNDTRIP("\"Hello\"");
	TEST_ROUNDTRIP("\"Hello\\nWorld\"");
	TEST_ROUNDTRIP("\"\\\" \\\\ / \\b \\f \\n \\r \\t\"");
	TEST_ROUNDTRIP("\"Hello\\u0000World\"");
}

static void test_stringify_array() {
	TEST_ROUNDTRIP("[]");
	TEST_ROUNDTRIP("[null,false,true,123,\"abc\",[1,2,3]]");
}

static void test_stringify_object() {
	TEST_ROUNDTRIP("{}");
	TEST_ROUNDTRIP("{\"n\":null,\"f\":false,\"t\":true,\"i\":123,\"s\":\"abc\",\"a\":[1,2,3],\"o\":{\"1\":1,\"2\":2,\"3\":3}}");
}

static void test_parse(){
	test_parse_null();
	test_parse_true();
	test_parse_false();
	test_parse_number();
	test_parse_object();
	test_parse_invalid_value();
	test_parse_root_not_sigular();
	test_parse_number_too_big();
	test_parse_string();
	test_parse_invalid_string_escape();
	test_parse_invalid_string_char();
	test_parse_missing_quotation_mark();
	test_parse_array();
	test_parse_miss_comma_or_square_bracket();
	test_parse_miss_key();
	test_parse_miss_comma_or_curly_bracket();
	test_parse_miss_colon();
}

#define TEST_EQUAL(json1, json2, equality) \
do {\
	json_value v1, v2; \
	json_init(&v1); \
	json_init(&v2); \
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v1, json1)); \
	EXPECT_EQ_INT(JSON_PARSE_OK, json_parse(&v2, json2)); \
	EXPECT_EQ_INT(equality, json_is_equal(&v1, &v2)); \
	json_free(&v1); \
	json_free(&v2); \
} while (0)

static void test_equal() {
	TEST_EQUAL("true", "true", 1);
	TEST_EQUAL("true", "false", 0);
	TEST_EQUAL("false", "false", 1);
	TEST_EQUAL("null", "null", 1);
	TEST_EQUAL("null", "0", 0);
	TEST_EQUAL("123", "123", 1);
	TEST_EQUAL("123", "456", 0);
	TEST_EQUAL("\"abc\"", "\"abc\"", 1);
	TEST_EQUAL("\"abc\"", "\"abcd\"", 0);
	TEST_EQUAL("[]", "[]", 1);
	TEST_EQUAL("[]", "null", 0);
	TEST_EQUAL("[1,2,3]", "[1,2,3]", 1);
	TEST_EQUAL("[1,2,3]", "[1,2,3,4]", 0);
	TEST_EQUAL("[[]]", "[[]]", 1);
	TEST_EQUAL("{}", "{}", 1);
	TEST_EQUAL("{}", "null", 0);
	TEST_EQUAL("{}", "[]", 0);
	TEST_EQUAL("{\"a\":1,\"b\":2}", "{\"a\":1,\"b\":2}", 1);
	TEST_EQUAL("{\"a\":1,\"b\":2}", "{\"b\":2,\"a\":1}", 1);
	TEST_EQUAL("{\"a\":1,\"b\":2}", "{\"a\":1,\"b\":3}", 0);
	TEST_EQUAL("{\"a\":1,\"b\":2}", "{\"a\":1,\"b\":2,\"c\":3}", 0);
	TEST_EQUAL("{\"a\":{\"b\":{\"c\":{}}}}", "{\"a\":{\"b\":{\"c\":{}}}}", 1);
	TEST_EQUAL("{\"a\":{\"b\":{\"c\":{}}}}", "{\"a\":{\"b\":{\"c\":[]}}}", 0);
}

static void test_copy() {
	json_value v1, v2;
	json_init(&v1);
	json_parse(&v1, "{\"t\":true,\"f\":false,\"n\":null,\"d\":1.5,\"a\":[1,2,3]}");
	json_init(&v2);
	json_copy(&v2, &v1);
	EXPECT_EQ_INT(1,json_is_equal(&v2, &v1));
	json_free(&v1);
	json_free(&v2);
}

static void test_move() {
	json_value v1, v2, v3;
	json_init(&v1);
	json_parse(&v1, "{\"t\":true,\"f\":false,\"n\":null,\"d\":1.5,\"a\":[1,2,3]}");
	json_init(&v2);
	json_copy(&v2, &v1);
	json_init(&v3);
	json_move(&v3, &v2);
	EXPECT_EQ_INT(JSON_NULL, json_get_type(&v2));
	EXPECT_EQ_INT(1,json_is_equal(&v3, &v1));
	json_free(&v1);
	json_free(&v2);
	json_free(&v3);
}

static void test_access_array() {
	json_value a, e;
	size_t i, j;

	json_init(&a);

	for (j = 0; j <= 5; j += 5) {
		json_set_array(&a, j);
		EXPECT_EQ_SIZE_T(0, json_get_array_size(&a));
		EXPECT_EQ_SIZE_T(j, json_get_array_capacity(&a));
		for (i = 0; i < 10; i++) {
			json_init(&e);
			json_set_number(&e, i);
			json_move(json_pushback_array_element(&a), &e);
			json_free(&e);
		}

		EXPECT_EQ_SIZE_T(10, json_get_array_size(&a));
		for (i = 0; i < 10; i++)
			EXPECT_EQ_DOUBLE((double)i, json_get_number(json_get_array_element(&a, i)));
	}

	json_popback_array_element(&a);
	EXPECT_EQ_SIZE_T(9, json_get_array_size(&a));
	for (i = 0; i < 9; i++)
		EXPECT_EQ_DOUBLE((double)i, json_get_number(json_get_array_element(&a, i)));

	json_erase_array_element(&a, 4, 0);
	EXPECT_EQ_SIZE_T(9, json_get_array_size(&a));
	for (i = 0; i < 9; i++)
		EXPECT_EQ_DOUBLE((double)i, json_get_number(json_get_array_element(&a, i)));

	json_erase_array_element(&a, 8, 1);
	EXPECT_EQ_SIZE_T(8, json_get_array_size(&a));
	for (i = 0; i < 8; i++)
		EXPECT_EQ_DOUBLE((double)i, json_get_number(json_get_array_element(&a, i)));

	json_erase_array_element(&a, 0, 2);
	EXPECT_EQ_SIZE_T(6, json_get_array_size(&a));
	for (i = 0; i < 6; i++)
		EXPECT_EQ_DOUBLE((double)i + 2, json_get_number(json_get_array_element(&a, i)));

	for (i = 0; i < 2; i++) {
		json_init(&e);
		json_set_number(&e, i);
		json_move(json_insert_array_element(&a, i), &e);
		json_free(&e);
	}

	EXPECT_EQ_SIZE_T(8, json_get_array_size(&a));
	for (i = 0; i < 8; i++)
		EXPECT_EQ_DOUBLE((double)i, json_get_number(json_get_array_element(&a, i)));

	EXPECT_EQ_INT(1,json_get_array_capacity(&a) > 8);
	json_shrink_array(&a);
	EXPECT_EQ_SIZE_T(8, json_get_array_capacity(&a));
	EXPECT_EQ_SIZE_T(8, json_get_array_size(&a));
	for (i = 0; i < 8; i++)
		EXPECT_EQ_DOUBLE((double)i, json_get_number(json_get_array_element(&a, i)));

	json_set_string(&e, "Hello", 5);
	json_move(json_pushback_array_element(&a), &e);     /* Test if element is freed */
	json_free(&e);

	i = json_get_array_capacity(&a);
	json_clear_array(&a);
	EXPECT_EQ_SIZE_T(0, json_get_array_size(&a));
	EXPECT_EQ_SIZE_T(i, json_get_array_capacity(&a));   /* capacity remains unchanged */
	json_shrink_array(&a);
	EXPECT_EQ_SIZE_T(0, json_get_array_capacity(&a));

	json_free(&a);
}

static void test_access_object() {
	json_value o, v, *pv;
	size_t i, j, index;

	json_init(&o);

	for (j = 0; j <= 5; j += 5) {
		json_set_object(&o, j);
		EXPECT_EQ_SIZE_T(0, json_get_object_size(&o));
		EXPECT_EQ_SIZE_T(j, json_get_object_capacity(&o));
		for (i = 0; i < 10; i++) {
			char key[2] = "a";
			key[0] += i;
			json_init(&v);
			json_set_number(&v, i);
			json_move(json_set_object_value(&o, key, 1), &v);
			json_free(&v);
		}
		EXPECT_EQ_SIZE_T(10, json_get_object_size(&o));
		for (i = 0; i < 10; i++) {
			char key[] = "a";
			key[0] += i;
			index = json_find_object_index(&o, key, 1);
			EXPECT_EQ_INT(1,index != JSON_KEY_NOT_EXIST);
			pv = json_get_object_value(&o, index);
			EXPECT_EQ_DOUBLE((double)i, json_get_number(pv));
		}
	}

	index = json_find_object_index(&o, "j", 1);
	EXPECT_EQ_INT(1,index != JSON_KEY_NOT_EXIST);
	json_remove_object_value(&o, index);
	index = json_find_object_index(&o, "j", 1);
	EXPECT_EQ_INT(1,index == JSON_KEY_NOT_EXIST);
	EXPECT_EQ_SIZE_T(9, json_get_object_size(&o));

	index = json_find_object_index(&o, "a", 1);
	EXPECT_EQ_INT(1,index != JSON_KEY_NOT_EXIST);
	json_remove_object_value(&o, index);
	index = json_find_object_index(&o, "a", 1);
	EXPECT_EQ_INT(1,index == JSON_KEY_NOT_EXIST);
	EXPECT_EQ_SIZE_T(8, json_get_object_size(&o));

	EXPECT_EQ_INT(1,json_get_object_capacity(&o) > 8);
	json_shrink_object(&o);
	EXPECT_EQ_SIZE_T(8, json_get_object_capacity(&o));
	EXPECT_EQ_SIZE_T(8, json_get_object_size(&o));
	for (i = 0; i < 8; i++) {
		char key[] = "a";
		key[0] += i + 1;
		EXPECT_EQ_DOUBLE((double)i + 1, json_get_number(json_get_object_value(&o, json_find_object_index(&o, key, 1))));
	}

	json_set_string(&v, "Hello", 5);
	json_move(json_set_object_value(&o, "World", 5), &v); /* Test if element is freed */
	json_free(&v);

	pv = json_find_object_value(&o, "World", 5);
	EXPECT_EQ_INT(1,pv != NULL);
	EXPECT_EQ_STRING("Hello", json_get_string(pv), json_get_string_lenth(pv));

	i = json_get_object_capacity(&o);
	json_clear_object(&o);
	EXPECT_EQ_SIZE_T(0, json_get_object_size(&o));
	EXPECT_EQ_SIZE_T(i, json_get_object_capacity(&o)); /* capacity remains unchanged */
	json_shrink_object(&o);
	EXPECT_EQ_SIZE_T(0, json_get_object_capacity(&o));

	json_free(&o);
}

static void test_swap() {
	json_value v1, v2;
	json_init(&v1);
	json_init(&v2);
	json_set_string(&v1, "Hello", 5);
	json_set_string(&v2, "World!", 6);
	json_swap(&v1, &v2);
	EXPECT_EQ_STRING("World!", json_get_string(&v1), json_get_string_lenth(&v1));
	EXPECT_EQ_STRING("Hello", json_get_string(&v2), json_get_string_lenth(&v2));
	json_free(&v1);
	json_free(&v2);
}

static void test_stringify(){
	TEST_ROUNDTRIP("null");
	TEST_ROUNDTRIP("false");
	TEST_ROUNDTRIP("true");
	test_stringify_number();
	test_stringify_string();
	test_stringify_array();
	test_stringify_object();
}

static void test_access(){
	test_access_string();
	test_access_boolean();
	test_access_number();
	test_access_array();
	test_access_object();
}

int main(){
#ifdef _WINDOWS
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
	test_parse();
	test_access();
	test_stringify();
	test_equal();
	test_move();
	test_copy();
	test_swap();
	printf("%d/%d (%3.2f%%) passed!",test_pass,test_count,100.0*test_pass/test_count);
	system("pause");
	return main_ret;
}