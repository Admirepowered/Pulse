import {type ReactNode, useMemo, useRef, useState} from 'react';

const yamlKeywords = [
    'mixed-port', 'port', 'socks-port', 'redir-port', 'tproxy-port', 'allow-lan', 'bind-address',
    'mode', 'log-level', 'ipv6', 'external-controller', 'external-ui', 'secret', 'authentication',
    'hosts', 'dns', 'enable', 'listen', 'enhanced-mode', 'fake-ip-range', 'nameserver', 'fallback',
    'fallback-filter', 'proxy-providers', 'proxies', 'proxy-groups', 'rule-providers', 'rules',
    'name', 'type', 'server', 'port', 'cipher', 'password', 'udp', 'skip-cert-verify', 'sni',
    'network', 'ws-opts', 'grpc-opts', 'reality-opts', 'path', 'headers', 'host', 'servername',
    'select', 'url-test', 'load-balance', 'relay', 'url', 'interval', 'health-check', 'lazy',
    'behavior', 'classical', 'domain', 'ipcidr', 'payload', 'tun', 'stack', 'auto-route',
    'auto-detect-interface', 'strict-route', 'mtu', 'sniffer', 'sniff', 'override-destination',
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'GEOSITE',
    'MATCH', 'DIRECT', 'REJECT', 'GLOBAL',
];

export function YamlEditor({value, onChange}: { value: string; onChange: (value: string) => void }) {
    const textareaRef = useRef<HTMLTextAreaElement | null>(null);
    const highlightRef = useRef<HTMLPreElement | null>(null);
    const [cursor, setCursor] = useState(0);
    const word = currentWord(value, cursor);
    const suggestions = useMemo(() => {
        if (word.text.length < 2) return [];
        const lower = word.text.toLowerCase();
        return yamlKeywords
            .filter((item) => item.toLowerCase().startsWith(lower) && item.toLowerCase() !== lower)
            .slice(0, 8);
    }, [word.text]);

    const applySuggestion = (suggestion: string) => {
        const next = value.slice(0, word.start) + suggestion + value.slice(cursor);
        const nextCursor = word.start + suggestion.length;
        onChange(next);
        window.requestAnimationFrame(() => {
            textareaRef.current?.focus();
            textareaRef.current?.setSelectionRange(nextCursor, nextCursor);
            setCursor(nextCursor);
        });
    };

    return (
        <div className="yamlEditor">
            <pre className="yamlHighlight" ref={highlightRef} aria-hidden="true">
                {highlightYaml(value)}
            </pre>
            <textarea
                ref={textareaRef}
                className="editor yamlTextarea"
                value={value}
                onChange={(event) => {
                    onChange(event.target.value);
                    setCursor(event.target.selectionStart);
                }}
                onClick={(event) => setCursor(event.currentTarget.selectionStart)}
                onKeyUp={(event) => setCursor(event.currentTarget.selectionStart)}
                onScroll={(event) => {
                    if (highlightRef.current) {
                        highlightRef.current.scrollTop = event.currentTarget.scrollTop;
                        highlightRef.current.scrollLeft = event.currentTarget.scrollLeft;
                    }
                }}
                onKeyDown={(event) => {
                    if (!suggestions.length) return;
                    if (event.key === 'Tab' || event.key === 'Enter') {
                        event.preventDefault();
                        applySuggestion(suggestions[0]);
                    }
                }}
                spellCheck={false}
            />
            {suggestions.length > 0 && (
                <div className="yamlSuggest">
                    {suggestions.map((suggestion) => (
                        <button key={suggestion} onMouseDown={(event) => {
                            event.preventDefault();
                            applySuggestion(suggestion);
                        }}>
                            {suggestion}
                        </button>
                    ))}
                </div>
            )}
        </div>
    );
}

function currentWord(value: string, cursor: number) {
    const before = value.slice(0, cursor);
    const match = before.match(/[A-Za-z0-9_-]+$/);
    const text = match?.[0] || '';
    return {text, start: cursor - text.length};
}

function highlightYaml(value: string) {
    const lines = value.split('\n');
    return lines.map((line, index) => (
        <span className="yamlLine" key={index}>
            {highlightLine(line)}
            {index < lines.length - 1 ? '\n' : ''}
        </span>
    ));
}

function highlightLine(line: string) {
    const commentIndex = line.indexOf('#');
    const code = commentIndex >= 0 ? line.slice(0, commentIndex) : line;
    const comment = commentIndex >= 0 ? line.slice(commentIndex) : '';
    const parts: ReactNode[] = [];
    const keyMatch = code.match(/^(\s*-?\s*)("?[\w.-]+"?)(\s*:)/);
    if (keyMatch) {
        parts.push(keyMatch[1]);
        parts.push(<span className="yamlKey" key="key">{keyMatch[2]}</span>);
        parts.push(<span className="yamlPunctuation" key="colon">{keyMatch[3]}</span>);
        parts.push(highlightValue(code.slice(keyMatch[0].length), 'value'));
    } else {
        parts.push(highlightValue(code, 'value'));
    }
    if (comment) parts.push(<span className="yamlComment" key="comment">{comment}</span>);
    return parts;
}

function highlightValue(value: string, keyPrefix: string) {
    const tokens = value.split(/(\b(?:true|false|null|DIRECT|REJECT|GLOBAL|MATCH|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|IP-CIDR6|GEOIP|GEOSITE)\b|\d+(?:\.\d+)?|"[^"]*"|'[^']*')/g);
    return tokens.map((token, index) => {
        if (/^['"]/.test(token)) return <span className="yamlString" key={`${keyPrefix}-${index}`}>{token}</span>;
        if (/^\d/.test(token)) return <span className="yamlNumber" key={`${keyPrefix}-${index}`}>{token}</span>;
        if (/^(true|false|null)$/i.test(token)) return <span className="yamlBool" key={`${keyPrefix}-${index}`}>{token}</span>;
        if (/^(DIRECT|REJECT|GLOBAL|MATCH|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|IP-CIDR6|GEOIP|GEOSITE)$/.test(token)) {
            return <span className="yamlRule" key={`${keyPrefix}-${index}`}>{token}</span>;
        }
        return token;
    });
}
