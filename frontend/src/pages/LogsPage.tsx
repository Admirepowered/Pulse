import {formatClock} from '../components/common';
import type {LogLine} from '../types';

export function LogsPage({logs}: { logs: LogLine[] }) {
    return (
        <article className="panel logs">
            {logs.slice().reverse().map((line, index) => (
                <div className={`logLine ${line.level}`} key={`${line.time}-${index}`}>
                    <span>{formatClock(line.time)}</span>
                    <strong>{line.level}</strong>
                    <p>{line.message}</p>
                </div>
            ))}
        </article>
    );
}
