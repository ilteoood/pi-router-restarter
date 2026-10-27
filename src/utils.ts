import { RouterError } from './router-error.ts';

export function toBase64(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64');
}

export function readScriptResult(script: string): number {
  const matches = [...script.matchAll(/\$\.ret\s*=\s*(-?\d+)/g)];
  const lastMatch = matches.at(-1);
  if (!lastMatch) throw new RouterError('Router response carried no result code');
  return Number(lastMatch[1]);
}

export function readAssignedString(source: string, name: string): string {
  const match = new RegExp(`var\\s+${name}\\s*=\\s*"([^"]*)"`).exec(source);
  const value = match?.[1];
  if (value === undefined) throw new RouterError(`Router did not provide "${name}"`);
  return value;
}
