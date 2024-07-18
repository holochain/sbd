/**
 * Prometheus label rendering helper.
 */
function renderLabels(labels: { [index: string]: any }): string {
  const out = ['{'];
  let isFirst = true;
  for (const key in labels) {
    if (isFirst) {
      isFirst = false;
    } else {
      out.push(',');
    }
    out.push(key);
    out.push('=');
    out.push(JSON.stringify(labels[key]));
  }
  if (isFirst) {
    return '';
  }
  out.push('}');
  return out.join('');
}

// All the npm modules I could find out there depended on nodejs apis.
// I just need a simple protocol renderer that can be used in cloudflare.

/**
 * Hand-rolled simplistic prometheus metrics renderer.
 */
export class Prom {
  #lines: Array<string>;

  constructor() {
    this.#lines = [];
  }

  /**
   * Generate a "guage" item.
   */
  guage(
    prepend: boolean,
    name: string,
    help: string,
    labels: { [index: string]: any },
    val: number,
  ) {
    if (prepend) {
      this.#lines.unshift('');
      this.#lines.unshift(`${name}${renderLabels(labels)} ${val}`);
      this.#lines.unshift(`# TYPE ${name} guage`);
      this.#lines.unshift(`# HELP ${name} ${help}`);
    } else {
      this.#lines.push(`# HELP ${name} ${help}`);
      this.#lines.push(`# TYPE ${name} guage`);
      this.#lines.push(`${name}${renderLabels(labels)} ${val}`);
      this.#lines.push('');
    }
  }

  /**
   * Render the previous generated prometheus line items into a single string.
   */
  render(): string {
    return this.#lines.join('\n');
  }
}
