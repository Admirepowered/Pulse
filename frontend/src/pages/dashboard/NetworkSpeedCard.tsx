import {ArrowDown, ArrowUp, Gauge} from 'lucide-react';
import {formatBytes} from '../../components/common';
import type {Translator} from '../../i18n';
import type {TrafficSnapshot} from '../../types';

export function NetworkSpeedCard({traffic, points, t}: {
    traffic: TrafficSnapshot;
    points: number[];
    t: Translator;
}) {
    const width = 420;
    const height = 142;
    const path = buildLinePath(points, width, height);
    const area = `${path} L ${width} ${height} L 0 ${height} Z`;

    return (
        <article className="networkCard">
            <div className="networkCardHead">
                <div>
                    <Gauge size={20}/>
                    <strong>{t('networkSpeed')}</strong>
                </div>
                <div className="speedLegend">
                    <span><ArrowUp size={14}/>{formatBytes(traffic.up)}/s</span>
                    <span><ArrowDown size={14}/>{formatBytes(traffic.down)}/s</span>
                </div>
            </div>
            <svg className="speedChart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
                <path className="speedArea" d={area}/>
                <path className="speedLine" d={path}/>
            </svg>
        </article>
    );
}

function buildLinePath(points: number[], width: number, height: number) {
    const values = points.length ? points : [0];
    const max = Math.max(1, ...values);
    if (values.length === 1) {
        const y = height - (values[0] / max) * (height - 18) - 8;
        return `M 0 ${y} L ${width} ${y}`;
    }
    return values.map((value, index) => {
        const x = (index / (values.length - 1)) * width;
        const y = height - (value / max) * (height - 18) - 8;
        return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
    }).join(' ');
}
