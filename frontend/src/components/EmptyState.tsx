// Shown in place of every page while nothing has been scanned or loaded (first start, or after Clear).
export default function EmptyState() {
  return (
    <section className="glass space-y-3 p-8">
      <h1 className="font-head text-3xl font-bold">No scan yet</h1>
      <p className="max-w-2xl text-lg text-paper/75">
        Scan a folder, a repository .zip or a public GitHub link above, or try the starter kit that ships with the
        app. The results appear on every page here: code and config, network, cloud, the CBOM and the roadmap.
      </p>
    </section>
  )
}
