import {useEffect, useState} from 'react';
import {Field} from '../../components/common';

export function AutoSaveField({label, value, type = 'text', placeholder, onDraft, onCommit}: {
    label: string;
    value: string;
    type?: string;
    placeholder?: string;
    onDraft?: (value: string) => void;
    onCommit: (value: string) => string | void;
}) {
    const [draft, setDraft] = useState(value);

    useEffect(() => {
        setDraft(value);
    }, [value]);

    const commit = () => {
        const next = onCommit(draft);
        if (typeof next === 'string') {
            setDraft(next);
        }
    };

    return (
        <Field
            label={label}
            type={type}
            value={draft}
            placeholder={placeholder}
            onChange={(next) => {
                setDraft(next);
                onDraft?.(next);
            }}
            onBlur={commit}
            onEnter={commit}
        />
    );
}
