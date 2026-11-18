package me.vespoli.secretbridge

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

sealed interface JsonValue

data object JsonNull : JsonValue
data class JsonBool(val value: Boolean) : JsonValue
data class JsonNum(val raw: String) : JsonValue {
    constructor(value: Int) : this(value.toString())
    constructor(value: Long) : this(value.toString())
    fun toInt(): Int = raw.toInt()
    fun toLong(): Long = raw.toLong()
}
data class JsonStr(val value: String) : JsonValue

/**
 * Ephemeral JSON string node backed by a mutable [CharArray] so bootstrap tokens
 * read from OS keychain never materialize as immutable [String] instances on the JVM heap.
 */
class JsonSecretChars(private val chars: CharArray) : JsonValue {
    fun writeEscapedUtf8(out: ByteArrayOutputStream) {
        out.write('"'.code)
        for (ch in chars) {
            writeEscapedCharUtf8(ch, out)
        }
        out.write('"'.code)
    }

    fun wipe() {
        chars.fill('\u0000')
    }
}

data class JsonArr(val items: List<JsonValue>) : JsonValue
data class JsonObj(val entries: Map<String, JsonValue>) : JsonValue {
    fun str(key: String): String? = (entries[key] as? JsonStr)?.value
    fun reqStr(key: String): String =
        str(key) ?: throw ProtocolCodecException("Missing or non-string JSON field '$key'")

    fun bool(key: String): Boolean? = (entries[key] as? JsonBool)?.value
    fun reqBool(key: String): Boolean =
        bool(key) ?: throw ProtocolCodecException("Missing or non-boolean JSON field '$key'")

    fun int(key: String): Int? = (entries[key] as? JsonNum)?.toInt()
    fun reqInt(key: String): Int =
        int(key) ?: throw ProtocolCodecException("Missing or non-integer JSON field '$key'")

    fun long(key: String): Long? = (entries[key] as? JsonNum)?.toLong()
    fun reqLong(key: String): Long =
        long(key) ?: throw ProtocolCodecException("Missing or non-long JSON field '$key'")

    fun obj(key: String): JsonObj? = entries[key] as? JsonObj
    fun reqObj(key: String): JsonObj =
        obj(key) ?: throw ProtocolCodecException("Missing or non-object JSON field '$key'")

    fun arr(key: String): List<JsonValue>? = (entries[key] as? JsonArr)?.items
    fun reqArr(key: String): List<JsonValue> =
        arr(key) ?: throw ProtocolCodecException("Missing or non-array JSON field '$key'")

    fun strList(key: String): List<String> =
        arr(key)?.map {
            (it as? JsonStr)?.value
                ?: throw ProtocolCodecException("Expected string element in array '$key'")
        } ?: emptyList()
}

class ProtocolCodecException(message: String) : IllegalArgumentException(message)

object JsonCodec {
    fun parse(input: CharSequence): JsonValue {
        val parser = Parser(input)
        val result = parser.parseValue()
        parser.skipWhitespace()
        if (!parser.isAtEnd()) {
            throw ProtocolCodecException("Unexpected trailing characters in JSON payload at index ${parser.pos}")
        }
        return result
    }

    fun parseObject(input: CharSequence): JsonObj =
        parse(input) as? JsonObj ?: throw ProtocolCodecException("Expected top-level JSON object")

    fun stringify(value: JsonValue): String {
        val bytes = encodeUtf8(value, appendNewline = false)
        return try {
            String(bytes, StandardCharsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * Encodes [value] directly to UTF-8 bytes (optionally terminated by '\n') and
     * deterministically wipes any [JsonSecretChars] nodes encountered, even on error.
     */
    fun encodeUtf8(value: JsonValue, appendNewline: Boolean = true): ByteArray {
        val out = ZeroizableByteArrayOutputStream(512)
        return try {
            writeUtf8(value, out)
            if (appendNewline) {
                out.write('\n'.code)
            }
            out.toByteArrayCopy()
        } finally {
            wipeSecretsRecursively(value)
            out.wipe()
        }
    }

    private fun wipeSecretsRecursively(value: JsonValue) {
        when (value) {
            is JsonSecretChars -> value.wipe()
            is JsonArr -> value.items.forEach(::wipeSecretsRecursively)
            is JsonObj -> value.entries.values.forEach(::wipeSecretsRecursively)
            JsonNull, is JsonBool, is JsonNum, is JsonStr -> Unit
        }
    }

    private fun writeUtf8(value: JsonValue, out: ByteArrayOutputStream) {
        when (value) {
            JsonNull -> out.write("null".toByteArray(StandardCharsets.US_ASCII))
            is JsonBool -> out.write(
                (if (value.value) "true" else "false").toByteArray(StandardCharsets.US_ASCII),
            )
            is JsonNum -> out.write(value.raw.toByteArray(StandardCharsets.US_ASCII))
            is JsonStr -> {
                out.write('"'.code)
                var i = 0
                while (i < value.value.length) {
                    val ch = value.value[i]
                    if (ch.isHighSurrogate() && i + 1 < value.value.length && value.value[i + 1].isLowSurrogate()) {
                        val cpBytes = value.value.substring(i, i + 2).toByteArray(StandardCharsets.UTF_8)
                        out.write(cpBytes)
                        i += 2
                        continue
                    }
                    writeEscapedCharUtf8(ch, out)
                    i += 1
                }
                out.write('"'.code)
            }
            is JsonSecretChars -> {
                try {
                    value.writeEscapedUtf8(out)
                } finally {
                    value.wipe()
                }
            }
            is JsonArr -> {
                out.write('['.code)
                value.items.forEachIndexed { idx, item ->
                    if (idx > 0) out.write(','.code)
                    writeUtf8(item, out)
                }
                out.write(']'.code)
            }
            is JsonObj -> {
                out.write('{'.code)
                var first = true
                for ((k, v) in value.entries) {
                    if (!first) out.write(','.code)
                    first = false
                    writeUtf8(JsonStr(k), out)
                    out.write(':'.code)
                    writeUtf8(v, out)
                }
                out.write('}'.code)
            }
        }
    }

    private class ZeroizableByteArrayOutputStream(size: Int) : ByteArrayOutputStream(size) {
        fun toByteArrayCopy(): ByteArray = buf.copyOf(count)
        fun wipe() {
            buf.fill(0)
            count = 0
        }
    }

    private class Parser(private val src: CharSequence) {
        var pos: Int = 0

        fun isAtEnd(): Boolean = pos >= src.length

        fun skipWhitespace() {
            while (pos < src.length) {
                when (src[pos]) {
                    ' ', '\t', '\r', '\n' -> pos++
                    else -> return
                }
            }
        }

        fun parseValue(): JsonValue {
            skipWhitespace()
            if (isAtEnd()) throw ProtocolCodecException("Unexpected end of JSON input")
            return when (val c = src[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> JsonStr(parseString())
                't' -> {
                    expectKeyword("true")
                    JsonBool(true)
                }
                'f' -> {
                    expectKeyword("false")
                    JsonBool(false)
                }
                'n' -> {
                    expectKeyword("null")
                    JsonNull
                }
                '-', in '0'..'9' -> parseNumber()
                else -> throw ProtocolCodecException("Unexpected character '$c' at index $pos")
            }
        }

        private fun expectKeyword(kw: String) {
            if (pos + kw.length > src.length || src.subSequence(pos, pos + kw.length).toString() != kw) {
                throw ProtocolCodecException("Invalid JSON literal at index $pos")
            }
            pos += kw.length
        }

        private fun parseObject(): JsonObj {
            pos++ // '{'
            skipWhitespace()
            val map = LinkedHashMap<String, JsonValue>()
            if (!isAtEnd() && src[pos] == '}') {
                pos++
                return JsonObj(map)
            }
            while (true) {
                skipWhitespace()
                if (isAtEnd() || src[pos] != '"') {
                    throw ProtocolCodecException("Expected string object key at index $pos")
                }
                val key = parseString()
                skipWhitespace()
                if (isAtEnd() || src[pos] != ':') {
                    throw ProtocolCodecException("Expected ':' after object key at index $pos")
                }
                pos++
                val value = parseValue()
                map[key] = value
                skipWhitespace()
                if (isAtEnd()) throw ProtocolCodecException("Unterminated JSON object")
                when (src[pos]) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        return JsonObj(map)
                    }
                    else -> throw ProtocolCodecException("Expected ',' or '}' in object at index $pos")
                }
            }
        }

        private fun parseArray(): JsonArr {
            pos++ // '['
            skipWhitespace()
            val items = ArrayList<JsonValue>()
            if (!isAtEnd() && src[pos] == ']') {
                pos++
                return JsonArr(items)
            }
            while (true) {
                items.add(parseValue())
                skipWhitespace()
                if (isAtEnd()) throw ProtocolCodecException("Unterminated JSON array")
                when (src[pos]) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        return JsonArr(items)
                    }
                    else -> throw ProtocolCodecException("Expected ',' or ']' in array at index $pos")
                }
            }
        }

        private fun parseString(): String {
            pos++ // '"'
            val sb = StringBuilder()
            while (pos < src.length) {
                val c = src[pos++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (pos >= src.length) throw ProtocolCodecException("Unterminated escape sequence")
                        when (val esc = src[pos++]) {
                            '"', '\\', '/' -> sb.append(esc)
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > src.length) {
                                    throw ProtocolCodecException("Incomplete unicode escape at index $pos")
                                }
                                val code = src.subSequence(pos, pos + 4).toString().toIntOrNull(16)
                                    ?: throw ProtocolCodecException("Invalid unicode hex escape at index $pos")
                                pos += 4
                                sb.append(code.toChar())
                            }
                            else -> throw ProtocolCodecException("Unsupported JSON escape '\\$esc'")
                        }
                    }
                    c.code < 0x20 -> throw ProtocolCodecException("Unescaped control character in JSON string")
                    else -> sb.append(c)
                }
            }
            throw ProtocolCodecException("Unterminated JSON string")
        }

        private fun parseNumber(): JsonNum {
            val start = pos
            if (src[pos] == '-') pos++
            if (pos >= src.length || src[pos] !in '0'..'9') {
                throw ProtocolCodecException("Invalid JSON number at index $start")
            }
            if (src[pos] == '0') {
                pos++
            } else {
                while (pos < src.length && src[pos] in '0'..'9') pos++
            }
            if (pos < src.length && src[pos] == '.') {
                pos++
                if (pos >= src.length || src[pos] !in '0'..'9') {
                    throw ProtocolCodecException("Invalid fraction in JSON number at index $start")
                }
                while (pos < src.length && src[pos] in '0'..'9') pos++
            }
            if (pos < src.length && (src[pos] == 'e' || src[pos] == 'E')) {
                pos++
                if (pos < src.length && (src[pos] == '+' || src[pos] == '-')) pos++
                if (pos >= src.length || src[pos] !in '0'..'9') {
                    throw ProtocolCodecException("Invalid exponent in JSON number at index $start")
                }
                while (pos < src.length && src[pos] in '0'..'9') pos++
            }
            return JsonNum(src.subSequence(start, pos).toString())
        }
    }
}

private val HEX_LOWER_ASCII = charArrayOf(
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
)

private fun writeEscapedCharUtf8(ch: Char, out: ByteArrayOutputStream) {
    when (ch) {
        '"' -> {
            out.write('\\'.code)
            out.write('"'.code)
        }
        '\\' -> {
            out.write('\\'.code)
            out.write('\\'.code)
        }
        '\b' -> {
            out.write('\\'.code)
            out.write('b'.code)
        }
        '\u000C' -> {
            out.write('\\'.code)
            out.write('f'.code)
        }
        '\n' -> {
            out.write('\\'.code)
            out.write('n'.code)
        }
        '\r' -> {
            out.write('\\'.code)
            out.write('r'.code)
        }
        '\t' -> {
            out.write('\\'.code)
            out.write('t'.code)
        }
        else -> {
            val code = ch.code
            when {
                code < 0x20 -> {
                    out.write('\\'.code)
                    out.write('u'.code)
                    out.write('0'.code)
                    out.write('0'.code)
                    out.write(HEX_LOWER_ASCII[(code shr 4) and 0x0F].code)
                    out.write(HEX_LOWER_ASCII[code and 0x0F].code)
                }
                code <= 0x7F -> out.write(code)
                code <= 0x7FF -> {
                    out.write(0xC0 or (code shr 6))
                    out.write(0x80 or (code and 0x3F))
                }
                else -> {
                    out.write(0xE0 or (code shr 12))
                    out.write(0x80 or ((code shr 6) and 0x3F))
                    out.write(0x80 or (code and 0x3F))
                }
            }
        }
    }
}
