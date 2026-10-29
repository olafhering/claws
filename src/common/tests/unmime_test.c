#include "config.h"

#include <stdio.h>
#include <glib.h>

#include "unmime.h"
#include "quoted-printable.h"

#include "mock_prefs_common_get_use_shred.h"
#include "mock_prefs_common_get_flush_metadata.h"

struct td {
	gchar *input;
	gboolean addr_field;
	gchar *expected_output;
};

struct td td_rfc2047_space1 = {
	input: "(=?ISO-8859-1?Q?a?=)",
	expected_output: "(a)"
};
struct td td_rfc2047_space2 = {
	input: "(=?ISO-8859-1?Q?a?= b)",
	expected_output: "(a b)"
};
struct td td_rfc2047_space3 = {
	input: "(=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?=)",
	expected_output: "(ab)"
};
struct td td_rfc2047_space4 = {
	input: "(=?ISO-8859-1?Q?a?=  =?ISO-8859-1?Q?b?=)",
	expected_output: "(ab)"
};
struct td td_rfc2047_space5 = {
	input: "(=?ISO-8859-1?Q?a?=\r\n =?ISO-8859-1?Q?b?=)",
	expected_output: "(ab)"
};
struct td td_rfc2047_space6 = {
	input: "(=?ISO-8859-1?Q?a_b?=)",
	expected_output: "(a b)"
};
struct td td_rfc2047_space7 = {
	input: "(=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?=)",
	expected_output: "(a b)"
};

struct td td_leading_whitespace = {
	input: " (=?ISO-8859-1?Q?a_b?=)",
	expected_output: " (a b)"
};
struct td td_with_quote = {
	input: "\"quote\" (=?ISO-8859-1?Q?a_b?=)",
	expected_output: "\"quote\" (a b)"
};
struct td td_in_quote = {
	input: "\"(=?ISO-8859-1?Q?a_b?=)\"",
	expected_output: "\"(=?ISO-8859-1?Q?a_b?=)\""
};
struct td td_nonconf_bad_quote = {
	input: "\"quote\r (=?ISO-8859-1?Q?a_b?=)\"",
	expected_output: "\"quote\r (a b)\""
};
struct td td_nonconf_bad_quote_2 = {
	input: "\"quote\r\n (=?ISO-8859-1?Q?a_b?=)\"",
	expected_output: "\"quote\r\n (a b)\""
};
struct td td_nonconf_split_utf8_encoding = {
	input: "=?utf-8?B?ICDD?="
	"\r\n"
	" =?utf-8?B?vH==?=",
	expected_output: "  ü"
};
struct td td_8859_1_word = {
	input: "Cache: =?iso-8859-1?q?M=FChlgassenh=FCtte?= (GCA0XJR)",
	expected_output: "Cache: Mühlgassenhütte (GCA0XJR)"
};

static void
test_unmime_header_null()
{
	if (!g_test_undefined())
		return;

	if (g_test_subprocess()) {
		gchar *out;

		out = unmime_header(NULL, FALSE);
		g_assert_null(out);
		g_free(out);
		return;
	}

	g_test_trap_subprocess(NULL, 0, 0);
	g_test_trap_assert_stdout("*Condition*failed*");
	g_test_trap_assert_passed();
}

static void
test_unmime_header(gconstpointer user_data)
{
	struct td *data = (struct td *)user_data;
	gchar *out = unmime_header(data->input, data->addr_field);

	g_assert_nonnull(out);
	g_assert_cmpstr(out, ==, data->expected_output);
	g_free(out);
}

int
main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/common/unmime/null",
			test_unmime_header_null);

	g_test_add_data_func("/common/unmime/rfc2047_space1",
			&td_rfc2047_space1,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/rfc2047_space2",
			&td_rfc2047_space2,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/rfc2047_space3",
			&td_rfc2047_space3,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/rfc2047_space4",
			&td_rfc2047_space4,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/rfc2047_space5",
			&td_rfc2047_space5,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/rfc2047_space6",
			&td_rfc2047_space6,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/rfc2047_space7",
			&td_rfc2047_space7,
			test_unmime_header);

	g_test_add_data_func("/common/unmime/leading_whitespace",
			&td_leading_whitespace,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/with_quote",
			&td_with_quote,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/in_quote",
			&td_in_quote,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/nonconf_bad_quote",
			&td_nonconf_bad_quote,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/nonconf_split_utf8_encoding",
			&td_nonconf_split_utf8_encoding,
			test_unmime_header);
	g_test_add_data_func("/common/unmime/4652_iso_8859_1_word", &td_8859_1_word, test_unmime_header);
	return g_test_run();
}
