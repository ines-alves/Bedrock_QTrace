// The engine names evidence whose algorithm it could not read (an encrypted key file) "unresolved".
// That is a gap in what was observed, never an algorithm, so every page words it the same way.
export const NOT_DETERMINABLE = 'Algorithm not determinable'

export const algorithmName = (name: string): string =>
  name.trim().toLowerCase() === 'unresolved' ? NOT_DETERMINABLE : name
