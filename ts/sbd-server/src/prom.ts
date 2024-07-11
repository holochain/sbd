function renderLabels(labels: object): string {
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

export class Prom {
  #lines: Array<string>;

  constructor() {
    this.#lines = [];
  }


  guage(prepend: boolean, name: string, help: string, labels: object, val: number) {
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

  render(): string {
    return this.#lines.join('\n');
  }
}
